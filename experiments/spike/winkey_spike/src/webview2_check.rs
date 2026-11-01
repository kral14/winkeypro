// WinKey Pro — WebView2 Mövcudluğunun Aşkarlanması və Clean-PC Məhdudiyyəti

use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum WebView2DetectionResult {
    DetectedOnHost { version: String, path: String },
    NotFound { fallback_download_url: String },
}

/// Yalnız mövcud host mühitində quraşdırılmış WebView2 runtime-ı aşkar edir (REAL_API).
/// DİQQƏT: Bu funksiya Clean-PC quraşdırma sübutu deyil!
/// Təmiz VM üzərində install testi NOT_TESTED olaraq saxlanılır.
pub fn check_host_webview2_installation() -> WebView2DetectionResult {
    let candidate_paths = [
        "C:\\Program Files (x86)\\Microsoft\\EdgeWebView\\Application",
        "C:\\Program Files\\Microsoft\\EdgeWebView\\Application",
    ];

    for path_str in &candidate_paths {
        let path = Path::new(path_str);
        if path.exists() {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    if file_name.chars().next().map_or(false, |c| c.is_ascii_digit())
                        && file_name.contains('.')
                    {
                        return WebView2DetectionResult::DetectedOnHost {
                            version: file_name,
                            path: path_str.to_string(),
                        };
                    }
                }
            }
        }
    }

    WebView2DetectionResult::NotFound {
        fallback_download_url: "https://go.microsoft.com/fwlink/p/?LinkId=2124703".to_string(),
    }
}
