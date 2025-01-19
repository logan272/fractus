use dioxus::logger::tracing::Level;
use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Routable, PartialEq)]
#[rustfmt::skip]
enum Route {
    #[layout(Navbar)]
    #[route("/")]
    DashboardPage {},
    #[route("/secrets")]
    SecretPage {},
}

const FAVICON: Asset = asset!("/assets/favicon.ico");
const MAIN_CSS: Asset = asset!("/assets/main.css");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

fn main() {
    dioxus::logger::init(Level::INFO).expect("logger failed to init");
    dioxus::launch(App);
}

#[component]
fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: MAIN_CSS }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        Router::<Route> {}
    }
}

/// Shared navbar component.
#[component]
fn Navbar() -> Element {
    rsx! {
        div { id: "navbar", display: "flex", gap: "1rem",
            Link { to: Route::DashboardPage {}, "Dashboard" }
            Link { to: Route::SecretPage {}, "Secret" }
        }

        Outlet::<Route> {}
    }
}

/// Home page
#[component]
fn DashboardPage() -> Element {
    rsx! {
        main { id: "dashboard-page",
            h1 { "SSS Dashboard" }
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
struct Secret {
    id: String,
    label: String,
    email: String,
    n: i32,
    k: i32,
    created_at: String,
}

/// Secret page
#[component]
pub fn SecretPage() -> Element {
    let secret = use_resource(|| async move {
        reqwest::get(format!(
            "http://localhost:3000/v1/secret?label={}",
            "LoganSecret"
        ))
        .await?
        .json::<Secret>()
        .await
    });

    rsx! {
        div { id: "secrets-page",
            h1 { "Secrets" }
            div {
                match &*secret.read_unchecked() {
                    Some(Ok(secret)) => {
                        rsx! {
                            ul { display: "flex", list_style: "none", gap: "1rem",
                                li { "Creator: {secret.email}" }
                                li { "Label: {secret.label}" }
                                li { "n: {secret.n}" }
                                li { "k: {secret.k}" }
                                li { "Created At: {secret.created_at}" }
                            }
                        }
                    }
                    Some(Err(err)) => rsx! {
                        p { "Failed to load secret: {err}" }
                    },
                    None => rsx! {
                        p { "Loading..." }
                    },
                }
            }
        }
    }
}
