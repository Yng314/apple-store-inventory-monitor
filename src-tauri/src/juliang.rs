//! 短效 HTTP 代理的提取、租期和失败等待；不保存或记录签名链接。

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use serde::Serialize;

const REFRESH_MARGIN: Duration = Duration::from_secs(30);

#[derive(Debug)]
struct Lease {
    address: SocketAddr,
    expires_at: Instant,
}

impl Lease {
    fn needs_refresh(&self, now: Instant) -> bool {
        self.expires_at.saturating_duration_since(now) <= REFRESH_MARGIN
    }
}

fn parse_lease(body: &[u8], now: Instant) -> Result<Lease, String> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| "巨量 IP 返回的内容不是有效 JSON".to_string())?;
    let code = value["code"].as_u64().unwrap_or_default();
    if code != 200 {
        // 不转发供应商原始响应，避免错误信息回显签名或完整提取链接。
        return Err(format!(
            "巨量 IP 提取失败（代码 {code}），请检查套餐余额、签名及出口 IP 白名单"
        ));
    }
    let entry = value["data"]["proxy_list"][0]
        .as_str()
        .ok_or("巨量 IP 未返回代理地址")?;
    let (address, remaining) = entry
        .split_once(',')
        .ok_or("巨量 IP 未返回剩余有效期，请在提取链接中启用 ip_remain=1")?;
    let address: SocketAddr = address
        .trim()
        .parse()
        .map_err(|_| "巨量 IP 返回的代理地址无效")?;
    if address.port() == 0 {
        return Err("巨量 IP 返回的代理端口无效".into());
    }
    let seconds: u64 = remaining
        .trim()
        .parse()
        .map_err(|_| "巨量 IP 返回的剩余有效期无效")?;
    if seconds <= REFRESH_MARGIN.as_secs() {
        return Err("巨量 IP 返回的代理即将过期，本次不使用，下轮重新提取".into());
    }
    let expires_at = now
        .checked_add(Duration::from_secs(seconds))
        .ok_or("巨量 IP 返回的剩余有效期无效")?;
    Ok(Lease {
        address,
        expires_at,
    })
}

fn api_url(value: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(value).map_err(|_| "请填写有效的巨量 IP 提取链接")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("巨量 IP 提取链接需使用 HTTP 或 HTTPS".into());
    }
    for (key, expected) in [
        ("num", "1"),
        ("pt", "1"),
        ("result_type", "json"),
        ("ip_remain", "1"),
    ] {
        if !url.query_pairs().any(|(k, v)| k == key && v == expected) {
            return Err(format!(
                "请在巨量 IP 重新生成提取链接，设置 {key}={expected}"
            ));
        }
    }
    Ok(url)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JuliangStatus {
    pub address: Option<String>,
    pub remaining_seconds: u64,
    pub retry_after_seconds: u64,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct JuliangPool {
    lease: Option<Lease>,
    retry_at: Option<Instant>,
    error: Option<String>,
}

impl JuliangPool {
    pub fn status(&self) -> JuliangStatus {
        let now = Instant::now();
        JuliangStatus {
            address: self.lease.as_ref().map(|lease| lease.address.to_string()),
            remaining_seconds: self.lease.as_ref().map_or(0, |lease| {
                lease.expires_at.saturating_duration_since(now).as_secs()
            }),
            retry_after_seconds: self.retry_at.map_or(0, |at| {
                at.saturating_duration_since(now)
                    .as_secs()
                    .saturating_add(u64::from(at > now))
            }),
            error: self.error.clone(),
        }
    }

    pub fn proxy_url(&self) -> Option<String> {
        self.lease
            .as_ref()
            .map(|lease| format!("http://{}", lease.address))
    }

    pub fn invalidate(&mut self, error: String, retry_delay: Duration) {
        self.lease = None;
        self.error = Some(error);
        self.retry_at = Some(Instant::now() + retry_delay);
    }

    /// 返回 true 表示出口已更换，调用方须重建专属查询浏览器。
    pub async fn ensure(&mut self, url: &str, retry_delay: Duration) -> Result<bool, String> {
        let now = Instant::now();
        if self
            .lease
            .as_ref()
            .is_some_and(|lease| !lease.needs_refresh(now))
        {
            return Ok(false);
        }
        if self.retry_at.is_some_and(|at| at > now) {
            return Err(self
                .error
                .clone()
                .unwrap_or_else(|| "巨量 IP 等待下轮重试".into()));
        }
        self.lease = None;
        let result = async {
            let url = api_url(url)?;
            // 提取接口与代理连接均不跟随环境代理，避免自动白名单授权到另一个出口。
            let client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(15))
                .build()
                .map_err(|_| "无法创建巨量 IP 提取客户端".to_string())?;
            let response = client
                .get(url)
                .send()
                .await
                .map_err(|_| "无法连接巨量 IP 提取接口，请检查网络和白名单".to_string())?;
            if !response.status().is_success() {
                return Err(format!(
                    "巨量 IP 提取接口返回 HTTP {}",
                    response.status().as_u16()
                ));
            }
            let body = response
                .bytes()
                .await
                .map_err(|_| "无法读取巨量 IP 提取结果".to_string())?;
            // 从发出提取请求起计时，不把网络耗时额外算进代理有效期。
            parse_lease(&body, now)
        }
        .await;
        match result {
            Ok(lease) => {
                self.lease = Some(lease);
                self.retry_at = None;
                self.error = None;
                Ok(true)
            }
            Err(error) => {
                self.invalidate(error.clone(), retry_delay);
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn 复用有效代理且临近到期才重新提取() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/getips?num=1&pt=1&result_type=json&ip_remain=1",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            assert!(stream.read(&mut buffer).await.unwrap() > 0);
            let body = r#"{"code":200,"msg":"success","data":{"count":1,"proxy_list":["127.0.0.1:8124,300"]}}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        });
        let mut pool = JuliangPool {
            lease: Some(Lease {
                address: "127.0.0.1:8123".parse().unwrap(),
                expires_at: Instant::now() + Duration::from_secs(120),
            }),
            ..JuliangPool::default()
        };
        assert!(!pool.ensure(&url, Duration::from_secs(30)).await.unwrap());
        assert_eq!(pool.proxy_url().as_deref(), Some("http://127.0.0.1:8123"));
        pool.lease.as_mut().unwrap().expires_at = Instant::now() + Duration::from_secs(29);
        assert!(pool.ensure(&url, Duration::from_secs(30)).await.unwrap());
        assert_eq!(pool.proxy_url().as_deref(), Some("http://127.0.0.1:8124"));
        assert!(!pool.ensure(&url, Duration::from_secs(30)).await.unwrap());
        assert!(server.await.unwrap(), "有效代理期间不应额外提取");
    }

    #[test]
    fn 按真实剩余寿命提前刷新而不是固定五分钟() {
        let now = Instant::now();
        let lease = parse_lease(
            br#"{"code":200,"data":{"proxy_list":["127.0.0.1:8123,120"]}}"#,
            now,
        )
        .unwrap();
        assert_eq!(lease.address.to_string(), "127.0.0.1:8123");
        assert!(!lease.needs_refresh(now + Duration::from_secs(89)));
        assert!(lease.needs_refresh(now + Duration::from_secs(90)));
    }

    #[test]
    fn 不接受缺失有效期或临近过期的代理() {
        for entry in ["127.0.0.1:8123", "127.0.0.1:8123,20", "not-a-proxy,300"] {
            let body = serde_json::json!({"code":200,"data":{"proxy_list":[entry]}});
            assert!(parse_lease(body.to_string().as_bytes(), Instant::now()).is_err());
        }
    }

    #[test]
    fn 供应商错误不把响应中的签名写进提示() {
        let err = parse_lease(
            br#"{"code":401,"msg":"sign=private-token","data":[]}"#,
            Instant::now(),
        )
        .unwrap_err();
        assert!(err.contains("401"));
        assert!(!err.contains("private-token"));
    }

    #[tokio::test]
    async fn 提取失败等待下轮且重复检查不再次提取() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/getips?num=1&pt=1&result_type=json&ip_remain=1&sign=private-token",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];
            assert!(stream.read(&mut buffer).await.unwrap() > 0);
            let body = r#"{"code":401,"msg":"private-token","data":[]}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        });
        let mut pool = JuliangPool::default();
        assert!(pool.ensure(&url, Duration::from_secs(30)).await.is_err());
        let err = pool
            .ensure(&url, Duration::from_secs(30))
            .await
            .unwrap_err();
        assert!(!err.contains("private-token"));
        assert!(pool.status().retry_after_seconds > 0);
        assert!(server.await.unwrap(), "等待期间不应再次访问提取接口");
    }
}
