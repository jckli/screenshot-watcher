use clipboard::{ClipboardContext, ClipboardProvider};
use dotenv::dotenv;
use futures::{
    channel::mpsc::{channel, Receiver},
    SinkExt, StreamExt,
};
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use reqwest::{multipart, Body, Client};
use std::env::var;
use std::path::Path;
use tokio::fs::File;
use tokio_util::codec::{BytesCodec, FramedRead};

#[tokio::main]
async fn main() {
    dotenv().ok();
    let path = var("DIRECTORY").expect("Expected DIRECTORY in the environment");
    futures::executor::block_on(async {
        if let Err(e) = async_watch(path).await {
            println!("error: {:?}", e)
        }
    });
}

fn async_watcher() -> notify::Result<(RecommendedWatcher, Receiver<notify::Result<Event>>)> {
    let (mut tx, rx) = channel(1);
    let watcher = RecommendedWatcher::new(
        move |res| {
            futures::executor::block_on(async {
                tx.send(res).await.unwrap();
            })
        },
        Config::default(),
    )?;

    Ok((watcher, rx))
}

async fn async_watch<P: AsRef<Path>>(path: P) -> notify::Result<()> {
    let (mut watcher, mut rx) = async_watcher()?;
    println!("Watching directory: {:?}", path.as_ref());
    watcher.watch(path.as_ref(), RecursiveMode::Recursive)?;

    while let Some(res) = rx.next().await {
        match res {
            Ok(event) => {
                if event.kind.is_create() {
                    let original_path = Path::new(&event.paths[0]).to_path_buf();
                    println!("Detected new file: {:?}", original_path);
                    let mut real_path = original_path.clone();
                    if var("ONEDRIVE").expect("Expected ONEDRIVE in the environment") == "true" {
                        let file_name = original_path.file_name().unwrap();
                        let file_name_str = file_name.to_str().unwrap();
                        let new_file_name = file_name_str.trim_start_matches(".");
                        let parent = original_path.parent().unwrap();
                        real_path = parent.join(new_file_name);
                    }
                    make_post_request(&real_path).await.unwrap();
                }
            }
            Err(e) => println!("watch error: {:?}", e),
        }
    }

    Ok(())
}

async fn make_post_request(path: &Path) -> reqwest::Result<()> {
    let client = Client::new();
    println!("Uploading file: {:?}", path);

    let pathname = Path::new(&path);
    let filename = pathname.file_name().unwrap();
    let mime_str = mime_guess::from_path(&path).first().unwrap();

    let file = File::open(path).await.unwrap();
    let stream = FramedRead::new(file, BytesCodec::new());
    let file_body = Body::wrap_stream(stream);
    let some_file = multipart::Part::stream(file_body)
        .file_name(filename.to_str().unwrap().to_string())
        .mime_str(mime_str.to_string().as_str())
        .unwrap();
    let form = multipart::Form::new().part("file", some_file);

    let link = format!(
        "https://{}/api/upload",
        var("LINK").expect("Expected LINK in the environment")
    );

    let response;
    if var("EMBED").expect("Expected EMBED in the environment") == "true" {
        response = client
            .post(link)
            .header(
                "Authorization",
                var("TOKEN").expect("Expected TOKEN in the environment"),
            )
            .header(
                "Format",
                var("FORMAT").expect("Expected FORMAT in the environment"),
            )
            .header("Embed", "true")
            .multipart(form);
    } else {
        response = client
            .post(link)
            .header(
                "Authorization",
                var("TOKEN").expect("Expected TOKEN in the environment"),
            )
            .header(
                "Format",
                var("FORMAT").expect("Expected FORMAT in the environment"),
            )
            .multipart(form);
    }
    let resp = response.send().await?;
    let response_body: serde_json::Value = resp.json().await?;
    let url = response_body["files"][0].as_str().unwrap();
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(url.to_string()).unwrap();

    println!("Set clipboard to: {}", url);

    Ok(())
}
