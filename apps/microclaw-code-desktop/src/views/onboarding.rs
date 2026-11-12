//! First run: no model is configured. Pick a provider, a model and a key;
//! `code-core::setup` writes `~/.mccode/config.yaml` (the same file
//! `mccode setup` writes), then the project starts again.

use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::select::{Select, SelectEvent, SelectState};
use gpui_kit::component::{ActiveTheme as _, h_flex, v_flex};
use gpui_kit::prelude::*;
use gpui_kit::*;
use microclaw_code_core::setup::{self, SetupChoice};

/// Emitted once the configuration is written.
pub struct OnboardingDone;

pub struct Onboarding {
    reason: String,
    providers: Entity<SelectState<Vec<String>>>,
    model: Entity<InputState>,
    api_key: Entity<InputState>,
    base_url: Entity<InputState>,
    provider: Option<String>,
    error: Option<String>,
    _subscriptions: Vec<Subscription>,
}

impl EventEmitter<OnboardingDone> for Onboarding {}

impl Onboarding {
    pub fn new(reason: String, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let ids: Vec<String> = setup::providers()
            .iter()
            .map(|p| p.id.to_string())
            .collect();
        let providers = cx.new(|cx| SelectState::new(ids, None, window, cx).searchable(true));
        let model = cx.new(|cx| InputState::new(window, cx).placeholder("Model"));
        let api_key = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("API key")
                .masked(true)
        });
        let base_url = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Base URL (leave empty for the default)")
        });
        let subscription = cx.subscribe_in(
            &providers,
            window,
            |this, _, event: &SelectEvent<Vec<String>>, window, cx| {
                let SelectEvent::Confirm(choice) = event;
                this.provider = choice.clone();
                let preset = setup::providers()
                    .into_iter()
                    .find(|p| Some(p.id) == choice.as_deref());
                let suggested = preset
                    .as_ref()
                    .and_then(|p| p.models.first().copied())
                    .unwrap_or("");
                let url = preset.as_ref().map(|p| p.default_base_url).unwrap_or("");
                this.model
                    .update(cx, |input, cx| input.set_value(suggested, window, cx));
                this.base_url
                    .update(cx, |input, cx| input.set_value(url, window, cx));
                cx.notify();
            },
        );
        Self {
            reason,
            providers,
            model,
            api_key,
            base_url,
            provider: None,
            error: None,
            _subscriptions: vec![subscription],
        }
    }

    fn save(&mut self, cx: &mut Context<Self>) {
        let choice = SetupChoice {
            provider: self.provider.clone().unwrap_or_default(),
            model: self.model.read(cx).value().to_string(),
            api_key: self.api_key.read(cx).value().to_string(),
            base_url: Some(self.base_url.read(cx).value().to_string()),
        };
        match setup::resolve(choice).and_then(|settings| setup::write(&settings)) {
            Ok(_) => {
                self.error = None;
                cx.emit(OnboardingDone);
            }
            Err(e) => self.error = Some(e.to_string()),
        }
        cx.notify();
    }
}

impl Render for Onboarding {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        let keyless = self.provider.as_deref().is_some_and(setup::keyless);
        let field = |label: &'static str, child: AnyElement| {
            v_flex()
                .gap_1()
                .child(div().text_sm().font_weight(FontWeight::MEDIUM).child(label))
                .child(child)
        };
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .child(
                v_flex()
                    .w(px(460.))
                    .gap_4()
                    .p_6()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .text_xl()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("Set up a model"),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme.muted_foreground)
                            .child(format!(
                                "MicroClaw Code needs a model provider. This writes {}, shared with the mccode command.",
                                microclaw_code_core::home::config_path().display()
                            )),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(theme.muted_foreground)
                            .child(self.reason.clone()),
                    )
                    .child(field(
                        "Provider",
                        Select::new(&self.providers)
                            .placeholder("Choose a provider")
                            .into_any_element(),
                    ))
                    .child(field("Model", Input::new(&self.model).into_any_element()))
                    .when(!keyless, |this| {
                        this.child(field(
                            "API key",
                            Input::new(&self.api_key).mask_toggle().into_any_element(),
                        ))
                    })
                    .child(field(
                        "Base URL",
                        Input::new(&self.base_url).into_any_element(),
                    ))
                    .when_some(self.error.clone(), |this, error| {
                        this.child(div().text_sm().text_color(theme.danger).child(error))
                    })
                    .child(
                        h_flex().justify_end().child(
                            Button::new("save-setup")
                                .primary()
                                .label("Save and start")
                                .on_click(cx.listener(|this, _, _, cx| this.save(cx))),
                        ),
                    ),
            )
            .text_color(theme.foreground)
    }
}
