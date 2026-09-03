#[derive(Clone, Copy)]
pub struct ChannelFieldDef {
    pub yaml_key: &'static str,
    pub label: &'static str,
    pub default: &'static str,
    pub secret: bool,
    pub required: bool,
}

#[derive(Clone, Copy)]
pub struct DynamicChannelDef {
    pub name: &'static str,
    pub presence_keys: &'static [&'static str],
    pub fields: &'static [ChannelFieldDef],
}
