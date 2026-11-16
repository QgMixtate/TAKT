//! SurveyScan agent (Rust, C52.02). Обмен с центром — тот же, что у Go-агента (C03/C15): каноническая форма
//! RFC 8785, подписи Ed25519 с доменным префиксом, mTLS к collector площадки. Модули добавляются по шагам
//! с проверкой побайтного совпадения с Go (testdata/).

pub mod canonical;
pub mod sign;
pub mod der;
pub mod machineid;
pub mod state;
