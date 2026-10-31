fn main() {
    println!("cargo:rerun-if-changed=../ui");
    println!("cargo:rerun-if-changed=../ui/index.html");
    println!("cargo:rerun-if-changed=../ui/app.js");
    println!("cargo:rerun-if-changed=tauri.conf.json");
    tauri_build::build();
}
