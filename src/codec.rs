use atoi::atoi;
use httparse::{Status, EMPTY_HEADER};
use hyper::{header, Request};

pub trait RequestExt {
    fn encode(buf: &mut Vec<u8>) -> Option<Self>
    where
        Self: Sized;
    fn decode(self) -> Vec<u8>;
}

impl RequestExt for Request<Vec<u8>> {
    fn encode(buf: &mut Vec<u8>) -> Option<Self> {
        let header_len = buf.iter().filter(|b| **b == b'\n').count();
        let mut headers = vec![EMPTY_HEADER; header_len];
        let mut req = httparse::Request::new(&mut headers);
        if let Ok(Status::Complete(header_len)) = req.parse(&buf.clone()) {
            let mut builder = Request::builder()
                .method(req.method.unwrap())
                .uri(req.path.unwrap());
            for header in req.headers.iter() {
                builder = builder.header(header.name, header.value);
            }

            let mut r: Request<Vec<u8>> = builder.body(vec![]).unwrap();
            let cl = match r.headers().get(header::CONTENT_LENGTH) {
                Some(header_value) => atoi::<usize>(header_value.as_bytes()).unwrap_or(0),
                None => 0,
            };
            if cl == 0 {
                buf.drain(..header_len);
                return Some(r);
            } else if buf.len() >= header_len + cl {
                buf.drain(..header_len);
                let body = buf.drain(..cl);
                r.body_mut().extend(body);
                return Some(r);
            }
        }
        None
    }

    fn decode(self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.method().as_str().as_bytes());
        buf.extend_from_slice(b" ");
        buf.extend_from_slice(self.uri().path().as_bytes());
        buf.extend_from_slice(b" HTTP/1.1\r\n");

        for (k, v) in self.headers() {
            buf.extend_from_slice(k.as_str().as_bytes());
            buf.extend_from_slice(b": ");
            buf.extend_from_slice(v.as_bytes());
            buf.extend_from_slice(b"\r\n");
        }

        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(self.body());
        buf
    }
}

#[test]
fn it_work() {
    let src = b"POST /_private/browser/errors HTTP/1.1\r\naccept: */*\r\naccept-encoding: gzip, deflate, br\r\naccept-language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6\r\nconnection: keep-alive\r\ncontent-length: 1188\r\ncontent-type: text/plain;charset=UTF-8\r\nhost: api.github.com\r\norigin: https://github.com\r\nreferer: https://github.com/thlstsul/json-prettier/blob/master/README.md\r\nsec-fetch-dest: empty\r\nsec-fetch-mode: cors\r\nsec-fetch-site: same-site\r\nuser-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.41\r\nsec-ch-ua: \"Microsoft Edge\";v=\"111\", \"Not(A:Brand\";v=\"8\", \"Chromium\";v=\"111\"\r\nsec-ch-ua-mobile: ?0\r\nsec-ch-ua-platform: \"Windows\"\r\n\r\n{\"error\":{\"type\":\"ChunkLoadError\",\"value\":\"Loading chunk vendors-node_modules_primer_behaviors_dist_esm_dimensions_js-node_modules_github_hotkey_dist_-9fc4f4 failed.\\n(missing: https://github.githubassets.com/assets/vendors-node_modules_primer_behaviors_dist_esm_dimensions_js-node_modules_github_hotkey_dist_-9fc4f4-d434ddaf3207.js)\",\"stacktrace\":[{\"filename\":\"https://github.githubassets.com/assets/wp-runtime-e2a8c60df2b4.js\",\"function\":\"t.f.j\",\"lineno\":\"1\",\"colno\":\"21211\"},{\"filename\":\"https://github.githubassets.com/assets/wp-runtime-e2a8c60df2b4.js\",\"function\":\"<unknown>\",\"lineno\":\"1\",\"colno\":\"1208\"},{\"filename\":\"<anonymous>\",\"function\":\"Array.reduce\",\"lineno\":\"0\",\"colno\":\"0\"},{\"filename\":\"https://github.githubassets.com/assets/wp-runtime-e2a8c60df2b4.js\",\"function\":\"t.e\",\"lineno\":\"1\",\"colno\":\"1187\"},{\"filename\":\"https://github.githubassets.com/assets/element-registry-418a6ca0b68e.js\",\"function\":\"<unknown>\",\"lineno\":\"1\",\"colno\":\"14224\"}]},\"sanitizedUrl\":\"https://github.com/<user-name>/<repo-name>/blob/show\",\"readyState\":\"interactive\",\"referrer\":\"https://github.com/thlstsul/json-prettier\",\"timeSinceLoad\":67,\"user\":\"thlstsul\",\"turbo\":true,\"bundler\":\"webpack\",\"ui\":false}";

    let r = Request::encode(&mut src.to_vec());
    if let Some(req) = r {
        assert_eq!(src, &req.decode()[..]);
    }
}
