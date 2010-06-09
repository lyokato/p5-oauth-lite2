package OAuth::Lite2::Error;

use strict;
use warnings;

use overload
    q{""}    => sub { shift->message },
    fallback => 1;

sub default_message { "error" }

sub new {
    my ($class, %args) = @_;
    bless {
        message => $args{message} || $class->default_message,
    }, $class;
}

sub throw {
    my ($class, %args) = @_;
    die $class->new(%args);
}

sub message {
    my $self = shift;
    return $self->{message};
}

package OAuth::Lite2::Error::AbstractMethod;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "abstract method" }

package OAuth::Lite2::Error::UnsupportedAlgorithm;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "unsupported algorithm" }

package OAuth::Lite2::Error::InvalidURIScheme;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "invalid uri scheme" }

package OAuth::Lite2::Error::InvalidFormat;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "invalid format" }

package OAuth::Lite2::Error::InvalidResponse;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "invalid response" }

package OAuth::Lite2::Error::InvalidParamMethod;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "invalid param method" }

# server errors

package OAuth::Lite2::Error::Server;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "server error" }

# not defined int the spec
package OAuth::Lite2::Error::Server::MissingParam;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "missing_param" }

package OAuth::Lite2::Error::Server::InvalidRefreshToken;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "invalid_refresh_token" }

package OAuth::Lite2::Error::Server::InvalidClient;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "invalid_client" }

package OAuth::Lite2::Error::Server::InvalidUser;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "invalid_user" }

package OAuth::Lite2::Error::Server::UnsupportedType;
our @ISA = qw(OAuth::Lite2::Error);
sub default_message { "unsupported_type" }

# defined in the spec
package OAuth::Lite2::Error::Server::UserDenied;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "user_denied" }

package OAuth::Lite2::Error::Server::RedirectURIMismatch;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "redirect_uri_mismatch" }

package OAuth::Lite2::Error::Server::BadVerificationCode;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "bad_verification_code" }

package OAuth::Lite2::Error::IncorrectClientCredentials;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "incorrect_client_credentials" }

package OAuth::Lite2::Error::AuthorizationDeclined;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "authorization_declined" }

package OAuth::Lite2::Error::AuthorizationPending;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "authorization_pending" }

package OAuth::Lite2::Error::SlowDown;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "slow_down" }

package OAuth::Lite2::Error::CodeExpired;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "code_expired" }

package OAuth::Lite2::Error::UnauthorizedClient;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "unauthorized_client" }

package OAuth::Lite2::Error::UnknownFormat;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "unknown_format" }

package OAuth::Lite2::Error::InvalidAssertion;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "invalid_assertion" }

package OAuth::Lite2::Error::AuthorizationExpired;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "authorization_expired" }

package OAuth::Lite2::Error::UnsupportedSecretType;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "unsupported_secret_type" }

package OAuth::Lite2::Error::TokenExpired;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "token_expired" }

package OAuth::Lite2::Error::InvalidSignature;
our @ISA = qw(OAuth::Lite2::Error::Server);
sub default_message { "invalid_signature" }

package OAuth::Lite2::Error;

1;
