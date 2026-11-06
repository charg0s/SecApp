function freeze(value) {
  if (value && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
}

export const WINDOWS_PROTECTION_PROFILE = freeze({
  id: "windows-protection-v1",
  version: "1.0.0",
  algorithm: "All required states must be known; any state differing from the expected value is a reported concern.",
  domains: [
    { area: "Defender", schema_id: "urn:secapp:observation:defender-protection:1", file: "defender-protection.schema.json", subject: "control:defender" },
    { area: "Firewall", schema_id: "urn:secapp:observation:firewall-profiles:1", file: "firewall-profiles.schema.json", subject: "control:firewall" },
    { area: "BitLocker", schema_id: "urn:secapp:observation:bitlocker-os-volume:1", file: "bitlocker-os-volume.schema.json", subject: "control:bitlocker-os-volume" },
    { area: "SecureBoot", schema_id: "urn:secapp:observation:secure-boot-state:1", file: "secure-boot-state.schema.json", subject: "control:secure-boot" }
  ],
  rules: [
    {
      id: "rule:secapp.defender-realtime", area: "Defender", title: "Defender: защита в реальном времени", severity: "Medium",
      checks: [{ field: "mode", known: ["Active"], expected: "Active" }, { field: "real_time_protection", known: ["Enabled", "Disabled"], expected: "Enabled" }],
      concern: "В снимке Defender указан как активный, но защита в реальном времени выключена.",
      normal: "В снимке активный Defender имеет включённую защиту в реальном времени.",
      limitation: "Другие антивирусы, исключения, актуальность баз и фактическое исполнение защиты не оценивались. Пассивный или неизвестный режим не считается безопасным результатом."
    },
    ...["Domain", "Private", "Public"].map((name) => ({
      id: `rule:secapp.firewall-${name.toLowerCase()}`, area: "Firewall", title: `Firewall: профиль ${name}`, severity: "Medium",
      checks: [{ field: name.toLowerCase(), known: ["Enabled", "Disabled"], expected: "Enabled" }],
      concern: `В снимке профиль Firewall ${name} выключен.`,
      normal: `В снимке профиль Firewall ${name} включён.`,
      limitation: "Текущий сетевой профиль, правила и эффективная объединённая политика не проверялись; доступность компьютера по сети из этого состояния не выводится."
    })),
    {
      id: "rule:secapp.bitlocker-os-volume", area: "BitLocker", title: "BitLocker: системный том", severity: "Medium",
      checks: [{ field: "protection", known: ["On", "Off"], expected: "On" }, { field: "encryption", known: ["FullyEncrypted", "PartiallyEncrypted", "NotEncrypted"], expected: "FullyEncrypted" }],
      concern: "В снимке системный том не полностью зашифрован или защита BitLocker выключена.",
      normal: "В снимке системный том полностью зашифрован, защита BitLocker включена.",
      limitation: "Другие тома, ключи восстановления, TPM и устойчивость к физическому доступу не оценивались."
    },
    {
      id: "rule:secapp.secure-boot", area: "SecureBoot", title: "Secure Boot", severity: "Low",
      checks: [{ field: "state", known: ["Enabled", "Disabled"], expected: "Enabled" }],
      concern: "В снимке Secure Boot выключен.",
      normal: "В снимке Secure Boot включён.",
      limitation: "Состояние прошивки и цепочки загрузки независимо не подтверждено. Неподдерживаемое состояние означает «Не проверено»."
    }
  ]
});
