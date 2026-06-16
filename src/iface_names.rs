/// Получает человекочитаемые имена сетевых интерфейсов Windows из реестра.
/// Ключ: HKLM\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-...}\{GUID}\Connection\Name
/// Возвращает HashMap<GUID_uppercase -> "Wi-Fi" / "Ethernet" / ...>
use std::collections::HashMap;

#[cfg(windows)]
pub fn get_friendly_names() -> HashMap<String, String> {
    use winreg::enums::*;
    use winreg::RegKey;

    let mut map = HashMap::new();

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let base_path = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

    let Ok(base_key) = hklm.open_subkey(base_path) else {
        return map;
    };

    for guid_result in base_key.enum_keys() {
        let Ok(guid) = guid_result else { continue };
        let conn_path = format!(r"{}\Connection", guid);
        let Ok(conn_key) = base_key.open_subkey(&conn_path) else {
            continue;
        };
        let Ok(name): Result<String, _> = conn_key.get_value("Name") else {
            continue;
        };
        // Нормализуем GUID к верхнему регистру без фигурных скобок для сопоставления
        let guid_clean = guid.trim_matches(|c| c == '{' || c == '}').to_uppercase();
        map.insert(guid_clean, name);
    }

    map
}

#[cfg(not(windows))]
pub fn get_friendly_names() -> std::collections::HashMap<String, String> {
    std::collections::HashMap::new()
}

/// Извлекает GUID из имени интерфейса вида \Device\NPF_{GUID}
pub fn extract_guid(iface_name: &str) -> Option<String> {
    let start = iface_name.find('{')? + 1;
    let end = iface_name.find('}')?;
    Some(iface_name[start..end].to_uppercase())
}
