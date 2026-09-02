//! Windows-specific shell compatibility support.
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

#[cfg(windows)]
const WINDOWS_POWERSHELL_COMPAT_SHIM: &str = r#"
$ProgressPreference = 'SilentlyContinue'

if (Test-Path Alias:curl) {
    Remove-Item Alias:curl -Force -ErrorAction SilentlyContinue
}

if (Test-Path Alias:wget) {
    Remove-Item Alias:wget -Force -ErrorAction SilentlyContinue
}

function __a3s_json_escape {
    param([string]$Value)
    if ($null -eq $Value) {
        return ''
    }

    $escaped = $Value.Replace('\', '\\').Replace('"', '\"')
    $escaped = $escaped.Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t')
    return $escaped
}

function __a3s_json_string {
    param([string]$Value)
    return '"' + (__a3s_json_escape $Value) + '"'
}

function __a3s_split_top_level {
    param([string]$Text)

    $parts = @()
    $current = New-Object System.Text.StringBuilder
    $braceDepth = 0
    $bracketDepth = 0
    $inSingle = $false
    $inDouble = $false

    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = $Text[$i]

        if ($ch -eq "'" -and -not $inDouble) {
            $inSingle = -not $inSingle
            [void]$current.Append($ch)
            continue
        }

        if ($ch -eq '"' -and -not $inSingle) {
            $escaped = $i -gt 0 -and $Text[$i - 1] -eq '\'
            if (-not $escaped) {
                $inDouble = -not $inDouble
            }
            [void]$current.Append($ch)
            continue
        }

        if (-not $inSingle -and -not $inDouble) {
            if ($ch -eq '{') {
                $braceDepth += 1
                [void]$current.Append($ch)
                continue
            } elseif ($ch -eq '}') {
                $braceDepth -= 1
                [void]$current.Append($ch)
                continue
            } elseif ($ch -eq '[') {
                $bracketDepth += 1
                [void]$current.Append($ch)
                continue
            } elseif ($ch -eq ']') {
                $bracketDepth -= 1
                [void]$current.Append($ch)
                continue
            } elseif ($ch -eq ',' -and $braceDepth -eq 0 -and $bracketDepth -eq 0) {
                $parts += $current.ToString()
                [void]$current.Clear()
                continue
            }
        }

        [void]$current.Append($ch)
    }

    if ($current.Length -gt 0) {
        $parts += $current.ToString()
    }

    return ,$parts
}

function __a3s_split_first_colon {
    param([string]$Text)

    $braceDepth = 0
    $bracketDepth = 0
    $inSingle = $false
    $inDouble = $false

    for ($i = 0; $i -lt $Text.Length; $i++) {
        $ch = $Text[$i]

        if ($ch -eq "'" -and -not $inDouble) {
            $inSingle = -not $inSingle
            continue
        }

        if ($ch -eq '"' -and -not $inSingle) {
            $escaped = $i -gt 0 -and $Text[$i - 1] -eq '\'
            if (-not $escaped) {
                $inDouble = -not $inDouble
            }
            continue
        }

        if (-not $inSingle -and -not $inDouble) {
            if ($ch -eq '{') {
                $braceDepth += 1
                continue
            } elseif ($ch -eq '}') {
                $braceDepth -= 1
                continue
            } elseif ($ch -eq '[') {
                $bracketDepth += 1
                continue
            } elseif ($ch -eq ']') {
                $bracketDepth -= 1
                continue
            } elseif ($ch -eq ':' -and $braceDepth -eq 0 -and $bracketDepth -eq 0) {
                return @($Text.Substring(0, $i), $Text.Substring($i + 1))
            }
        }
    }

    return $null
}

function __a3s_normalize_json_like {
    param([string]$Value)

    if ($null -eq $Value) {
        return $Value
    }

    $trimmed = $Value.Trim()
    if ($trimmed.Length -eq 0) {
        return $trimmed
    }

    try {
        $null = $trimmed | ConvertFrom-Json -ErrorAction Stop
        return $trimmed
    } catch {
    }

    if (($trimmed.StartsWith('"') -and $trimmed.EndsWith('"')) -or ($trimmed.StartsWith("'") -and $trimmed.EndsWith("'"))) {
        return __a3s_json_string $trimmed.Substring(1, $trimmed.Length - 2)
    }

    if ($trimmed -match '^(?i:true|false|null)$') {
        return $trimmed.ToLowerInvariant()
    }

    if ($trimmed -match '^-?\d+(\.\d+)?([eE][+-]?\d+)?$') {
        return $trimmed
    }

    if ($trimmed.StartsWith('{') -and $trimmed.EndsWith('}')) {
        $inner = $trimmed.Substring(1, $trimmed.Length - 2)
        if ([string]::IsNullOrWhiteSpace($inner)) {
            return '{}'
        }

        $normalizedParts = @()
        foreach ($pair in (__a3s_split_top_level $inner)) {
            $candidate = $pair.Trim()
            if ($candidate.Length -eq 0) {
                continue
            }

            $kv = __a3s_split_first_colon $candidate
            if ($null -eq $kv -or $kv.Count -ne 2) {
                return $trimmed
            }

            $key = $kv[0].Trim()
            if (($key.StartsWith('"') -and $key.EndsWith('"')) -or ($key.StartsWith("'") -and $key.EndsWith("'"))) {
                $key = $key.Substring(1, $key.Length - 2)
            }

            $normalizedValue = __a3s_normalize_json_like $kv[1]
            $normalizedParts += ((__a3s_json_string $key) + ':' + $normalizedValue)
        }

        return '{' + ($normalizedParts -join ',') + '}'
    }

    if ($trimmed.StartsWith('[') -and $trimmed.EndsWith(']')) {
        $inner = $trimmed.Substring(1, $trimmed.Length - 2)
        if ([string]::IsNullOrWhiteSpace($inner)) {
            return '[]'
        }

        $normalizedItems = @()
        foreach ($item in (__a3s_split_top_level $inner)) {
            $candidate = $item.Trim()
            if ($candidate.Length -eq 0) {
                continue
            }
            $normalizedItems += (__a3s_normalize_json_like $candidate)
        }

        return '[' + ($normalizedItems -join ',') + ']'
    }

    return __a3s_json_string $trimmed
}

function __a3s_prepare_curl_args {
    param([object[]]$Args)

    $rewritten = @()
    $jsonFlags = @('-d', '--data', '--data-raw', '--data-binary', '--json')

    for ($i = 0; $i -lt $Args.Count; $i++) {
        $arg = [string]$Args[$i]
        $handled = $false

        foreach ($flag in $jsonFlags) {
            $prefix = $flag + '='
            if ($arg.StartsWith($prefix)) {
                $value = $arg.Substring($prefix.Length)
                $rewritten += ($flag + '=' + (__a3s_normalize_json_like $value))
                $handled = $true
                break
            }
        }

        if ($handled) {
            continue
        }

        $rewritten += $Args[$i]
        if ($jsonFlags -contains $arg -and $i + 1 -lt $Args.Count) {
            $i += 1
            $rewritten += (__a3s_normalize_json_like ([string]$Args[$i]))
        }
    }

    return ,$rewritten
}

function __a3s_curl {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Args)
    $PreparedArgs = __a3s_prepare_curl_args $Args
    & curl.exe @PreparedArgs
}

function curl {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Args)
    __a3s_curl @Args
}

function wget {
    param([Parameter(ValueFromRemainingArguments = $true)][object[]]$Args)
    __a3s_curl @Args
}

function __a3s_http {
    param(
        [Parameter(Mandatory = $true)][string]$Method,
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(ValueFromRemainingArguments = $true)][object[]]$Args
    )
    __a3s_curl -sS -X $Method $Uri @Args
}

function GET {
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Uri,
        [Parameter(ValueFromRemainingArguments = $true)][object[]]$Args
    )
    __a3s_http GET $Uri @Args
}

function POST {
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Uri,
        [Parameter(ValueFromRemainingArguments = $true)][object[]]$Args
    )
    __a3s_http POST $Uri @Args
}

function PUT {
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Uri,
        [Parameter(ValueFromRemainingArguments = $true)][object[]]$Args
    )
    __a3s_http PUT $Uri @Args
}

function PATCH {
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Uri,
        [Parameter(ValueFromRemainingArguments = $true)][object[]]$Args
    )
    __a3s_http PATCH $Uri @Args
}

function DELETE {
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Uri,
        [Parameter(ValueFromRemainingArguments = $true)][object[]]$Args
    )
    __a3s_http DELETE $Uri @Args
}

function OPTIONS {
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Uri,
        [Parameter(ValueFromRemainingArguments = $true)][object[]]$Args
    )
    __a3s_http OPTIONS $Uri @Args
}

function head {
    param(
        [Parameter(Position = 0)]
        [string]$CountArg = '10',
        [Parameter(ValueFromPipeline = $true, Position = 1)]
        $InputObject
    )

    begin {
        if ($CountArg -match '^-\d+$') {
            $count = [int]$CountArg.Substring(1)
        } elseif ($CountArg -match '^\d+$') {
            $count = [int]$CountArg
        } else {
            $count = 10
        }
        $remaining = $count
    }

    process {
        if ($remaining -gt 0) {
            $InputObject
            $remaining -= 1
        }
    }
}

function which {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Name)
    foreach ($item in $Name) {
        $cmd = Get-Command $item -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -ne $cmd) {
            if ($cmd.Source) {
                $cmd.Source
            } else {
                $cmd.Name
            }
        }
    }
}
"#;

#[cfg(windows)]
pub(super) fn build_powershell_command(command: &str) -> String {
    format!(
        "{WINDOWS_POWERSHELL_COMPAT_SHIM}\n{}",
        preprocess_windows_command(command)
    )
}

#[cfg(windows)]
pub(super) fn encode_powershell_command(command: &str) -> String {
    let utf16_le: Vec<u8> = command
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    BASE64_STANDARD.encode(utf16_le)
}

#[cfg(windows)]
pub(super) fn preprocess_windows_command(command: &str) -> String {
    let trimmed = command.trim_start();
    let leading_ws_len = command.len() - trimmed.len();
    let token_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let token = &trimmed[..token_end];
    let rest = &trimmed[token_end..];

    let is_native_curl = matches!(token, "curl" | "curl.exe" | "wget" | "wget.exe")
        && !rest.trim_start().starts_with("--%");

    if is_native_curl {
        format!(
            "{}{} --%{}",
            &command[..leading_ws_len],
            if token.starts_with("wget") {
                "curl.exe"
            } else {
                token
            },
            rewrite_curl_json_literals(rest, true)
        )
    } else if matches!(token, "curl" | "curl.exe" | "wget" | "wget.exe")
        && rest.trim_start().starts_with("--%")
    {
        // PowerShell's stop-parsing token makes the remainder literal. Do
        // not normalize or quote payloads that the caller explicitly marked
        // as verbatim.
        command.to_owned()
    } else {
        rewrite_curl_json_literals(command, false)
    }
}

#[cfg(windows)]
fn rewrite_curl_json_literals(command: &str, verbatim_mode: bool) -> String {
    const FLAGS: [&str; 5] = ["--data-raw", "--data-binary", "--data", "-d", "--json"];

    let bytes = command.as_bytes();
    let mut out = String::with_capacity(command.len() + 16);
    let mut i = 0usize;

    while i < bytes.len() {
        let mut matched_flag = None;
        for flag in FLAGS {
            if command[i..].starts_with(flag) {
                let before_ok = i == 0 || command[..i].chars().last().unwrap().is_whitespace();
                let after = i + flag.len();
                let after_ok = after >= bytes.len()
                    || bytes[after].is_ascii_whitespace()
                    || bytes[after] == b'=';
                if before_ok && after_ok {
                    matched_flag = Some(flag);
                    break;
                }
            }
        }

        let Some(flag) = matched_flag else {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        };

        out.push_str(flag);
        i += flag.len();

        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            out.push(bytes[j] as char);
            j += 1;
        }

        if j < bytes.len() && bytes[j] == b'=' {
            out.push('=');
            j += 1;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                out.push(bytes[j] as char);
                j += 1;
            }
        }

        if let Some((literal, end)) = extract_unquoted_json_like_literal(command, j) {
            let normalized = normalize_json_like_literal(&literal).unwrap_or(literal);
            if verbatim_mode {
                out.push_str(&normalized);
            } else {
                out.push('\'');
                out.push_str(&normalized.replace('\'', "''"));
                out.push('\'');
            }
            i = end;
        } else {
            i = j;
        }
    }

    out
}

#[cfg(windows)]
fn extract_unquoted_json_like_literal(command: &str, start: usize) -> Option<(String, usize)> {
    let bytes = command.as_bytes();
    if start >= bytes.len() {
        return None;
    }

    let first = bytes[start];
    if first == b'\'' || first == b'"' || first != b'{' {
        return None;
    }

    let mut brace_depth = 0i32;
    let mut bracket_depth = 0i32;
    let mut in_single = false;
    let mut in_double = false;
    let mut i = start;

    while i < bytes.len() {
        let ch = bytes[i] as char;
        if ch == '\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if ch == '"' && !in_single {
            let escaped = i > start && bytes[i - 1] == b'\\';
            if !escaped {
                in_double = !in_double;
            }
            i += 1;
            continue;
        }

        if !in_single && !in_double {
            match ch {
                '{' => brace_depth += 1,
                '}' => {
                    brace_depth -= 1;
                    if brace_depth == 0 && bracket_depth == 0 {
                        let end = i + 1;
                        let literal = command[start..end].to_string();
                        return Some((literal, end));
                    }
                }
                '[' => bracket_depth += 1,
                ']' => bracket_depth -= 1,
                _ => {}
            }
        }

        i += 1;
    }

    None
}

#[cfg(windows)]
pub(super) fn normalize_json_like_literal(input: &str) -> Option<String> {
    // Let the standards-compliant parser handle already-valid JSON first.
    // Besides producing a compact representation, this preserves escapes
    // such as UTF-16 surrogate pairs that the PowerShell compatibility parser
    // should not reinterpret.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input) {
        return serde_json::to_string(&value).ok();
    }
    let mut parser = JsonLikeParser::new(input);
    let value = parser.parse_value()?;
    parser.skip_ws();
    if parser.is_eof() {
        Some(value)
    } else {
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn normalizes_scalars_and_nested_json_like_values() {
        assert_eq!(
            normalize_json_like_literal("'hello'"),
            Some("\"hello\"".into())
        );
        assert_eq!(normalize_json_like_literal("true"), Some("true".into()));
        assert_eq!(normalize_json_like_literal("42.5"), Some("42.5".into()));
        assert_eq!(
            normalize_json_like_literal("{name: 'A3S', enabled: true, items: [1, null]}"),
            Some(r#"{"name":"A3S","enabled":true,"items":[1,null]}"#.into())
        );
        assert_eq!(
            normalize_json_like_literal(r#"{message: "line\n\ud83d\ude00"}"#),
            Some(r#"{"message":"line\n😀"}"#.into())
        );
    }

    #[test]
    fn preserves_valid_json_escaping_and_rejects_malformed_literals() {
        assert_eq!(
            normalize_json_like_literal(r#"{"message":"line\n\ud83d\ude00"}"#),
            Some(r#"{"message":"line\n😀"}"#.into())
        );
        for malformed in ["{name:}", "[1,]", "{name 'missing-colon'}"] {
            assert_eq!(normalize_json_like_literal(malformed), None, "{malformed}");
        }
    }

    #[test]
    fn rewrites_curl_json_payloads_without_touching_unrelated_arguments() {
        assert_eq!(
            preprocess_windows_command("curl -sS -d {name: 'A3S'} https://example.test"),
            "curl --% -sS -d {\"name\":\"A3S\"} https://example.test"
        );
        assert_eq!(
            preprocess_windows_command("  wget --data={ok:true} https://example.test"),
            "  curl.exe --% --data={\"ok\":true} https://example.test"
        );
        assert_eq!(
            preprocess_windows_command("curl --% -d {already:json} https://example.test"),
            "curl --% -d {already:json} https://example.test"
        );
        assert_eq!(
            preprocess_windows_command("echo --data {not:curl}"),
            "echo --data '{\"not\":\"curl\"}'"
        );
    }

    #[test]
    fn encoded_commands_round_trip_utf16() {
        let command = "Write-Output '你好 🌍'";
        let encoded = encode_powershell_command(command);
        let bytes = BASE64_STANDARD.decode(encoded).unwrap();
        let units = bytes
            .chunks(2)
            .map(|pair| {
                assert_eq!(pair.len(), 2);
                u16::from_le_bytes([pair[0], pair[1]])
            })
            .collect::<Vec<_>>();
        assert_eq!(String::from_utf16(&units).unwrap(), command);
    }
}

#[cfg(windows)]
struct JsonLikeParser<'a> {
    chars: Vec<char>,
    pos: usize,
    _input: &'a str,
}

#[cfg(windows)]
impl<'a> JsonLikeParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
            _input: input,
        }
    }

    fn is_eof(&self) -> bool {
        self.pos >= self.chars.len()
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn next(&mut self) -> Option<char> {
        let ch = self.peek()?;
        self.pos += 1;
        Some(ch)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(ch) if ch.is_whitespace()) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self) -> Option<String> {
        self.skip_ws();
        match self.peek()? {
            '{' => self.parse_object(),
            '[' => self.parse_array(),
            '"' | '\'' => {
                let s = self.parse_quoted_string()?;
                serde_json::to_string(&s).ok()
            }
            _ => self.parse_bare_token(),
        }
    }

    fn parse_object(&mut self) -> Option<String> {
        self.expect('{')?;
        self.skip_ws();
        let mut entries = Vec::new();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Some("{}".to_string());
        }

        loop {
            self.skip_ws();
            let key = match self.peek()? {
                '"' | '\'' => self.parse_quoted_string()?,
                _ => self.parse_bare_key()?,
            };
            self.skip_ws();
            self.expect(':')?;
            let value = self.parse_value()?;
            entries.push(format!("{}:{}", serde_json::to_string(&key).ok()?, value));
            self.skip_ws();
            match self.peek()? {
                ',' => {
                    self.pos += 1;
                }
                '}' => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }

        Some(format!("{{{}}}", entries.join(",")))
    }

    fn parse_array(&mut self) -> Option<String> {
        self.expect('[')?;
        self.skip_ws();
        let mut values = Vec::new();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Some("[]".to_string());
        }

        loop {
            let value = self.parse_value()?;
            values.push(value);
            self.skip_ws();
            match self.peek()? {
                ',' => {
                    self.pos += 1;
                }
                ']' => {
                    self.pos += 1;
                    break;
                }
                _ => return None,
            }
        }

        Some(format!("[{}]", values.join(",")))
    }

    fn parse_quoted_string(&mut self) -> Option<String> {
        let quote = self.next()?;
        let mut out = String::new();
        while let Some(ch) = self.next() {
            if ch == '\\' {
                let escaped = self.next()?;
                match escaped {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'u' => {
                        let first = self.parse_hex_u16()?;
                        let code_point = if (0xd800..=0xdbff).contains(&first) {
                            if self.next()? != '\\' || self.next()? != 'u' {
                                return None;
                            }
                            let second = self.parse_hex_u16()?;
                            if !(0xdc00..=0xdfff).contains(&second) {
                                return None;
                            }
                            0x1_0000
                                + ((u32::from(first) - 0xd800) << 10)
                                + (u32::from(second) - 0xdc00)
                        } else if (0xdc00..=0xdfff).contains(&first) {
                            return None;
                        } else {
                            u32::from(first)
                        };
                        out.push(char::from_u32(code_point)?);
                    }
                    other => out.push(other),
                }
                continue;
            }
            if ch == quote {
                return Some(out);
            }
            out.push(ch);
        }
        None
    }

    fn parse_hex_u16(&mut self) -> Option<u16> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let digit = self.next()?.to_digit(16)?;
            value = value
                .checked_mul(16)?
                .checked_add(u16::try_from(digit).ok()?)?;
        }
        Some(value)
    }

    fn parse_bare_key(&mut self) -> Option<String> {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == ':' || ch == ',' || ch == '}' || ch.is_whitespace() {
                break;
            }
            self.pos += 1;
        }
        let key: String = self.chars[start..self.pos].iter().collect();
        let trimmed = key.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn parse_bare_token(&mut self) -> Option<String> {
        let start = self.pos;
        while let Some(ch) = self.peek() {
            if ch == ',' || ch == ']' || ch == '}' {
                break;
            }
            self.pos += 1;
        }
        let token: String = self.chars[start..self.pos].iter().collect();
        let trimmed = token.trim();
        if trimmed.is_empty() {
            return None;
        }
        if matches!(trimmed, "true" | "false" | "null") {
            return Some(trimmed.to_string());
        }
        if trimmed.parse::<i64>().is_ok() || trimmed.parse::<f64>().is_ok() {
            return Some(trimmed.to_string());
        }
        serde_json::to_string(trimmed).ok()
    }

    fn expect(&mut self, expected: char) -> Option<()> {
        self.skip_ws();
        match self.next()? {
            ch if ch == expected => Some(()),
            _ => None,
        }
    }
}
