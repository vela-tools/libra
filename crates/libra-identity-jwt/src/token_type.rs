//! The `typ` header an access token must carry (RFC 9068 sections 2.1 and 4).

use libra_config::jwt::AccessTokenType;

/// The `typ` value RFC 9068 section 2.1 recommends for a JWT access token.
const AT_JWT: &str = "at+jwt";

/// The same type spelled as a full media type, which section 4 requires a resource server to accept
/// as well.
const AT_JWT_MEDIA_TYPE: &str = "application/at+jwt";

/// Whether a token whose header carries `typ` may be used as an access token under `required`.
///
/// The comparison ignores case, because RFC 7515 section 4.1.9 makes a `typ` a media type and media
/// type names are case-insensitive. A token with no `typ` at all does not satisfy a requirement.
#[must_use]
pub fn admits(required: AccessTokenType, typ: Option<&str>) -> bool {
    match required {
        AccessTokenType::Any => true,
        AccessTokenType::AtJwt => typ.is_some_and(|typ| typ.eq_ignore_ascii_case(AT_JWT) || typ.eq_ignore_ascii_case(AT_JWT_MEDIA_TYPE)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_type_is_admitted_when_none_is_required() {
        for typ in [None, Some("JWT"), Some("at+jwt"), Some("id_token"), Some("")] {
            assert!(admits(AccessTokenType::Any, typ), "{typ:?}");
        }
    }

    #[test]
    fn both_spellings_of_the_access_token_type_are_admitted_in_any_case() {
        for typ in ["at+jwt", "AT+JWT", "At+Jwt", "application/at+jwt", "Application/AT+JWT"] {
            assert!(admits(AccessTokenType::AtJwt, Some(typ)), "{typ}");
        }
    }

    #[test]
    fn any_other_type_or_none_is_refused_when_the_access_token_type_is_required() {
        for typ in [
            None,
            Some("JWT"),
            Some("jwt"),
            Some("id_token"),
            Some(""),
            Some("at+jwt "),
            Some("at+jwt+x"),
            Some("application/jwt"),
        ] {
            assert!(!admits(AccessTokenType::AtJwt, typ), "{typ:?}");
        }
    }
}
