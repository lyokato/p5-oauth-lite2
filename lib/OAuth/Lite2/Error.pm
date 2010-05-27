package OAuth::Lite2::Error;

use strict;
use warnings;

sub new {
    my ($class, %args) = @_;
    bless {%args}, $class;
}

sub throw {
    my ($class, %args) = @_;
    die $class->new(%args);
}

package OAuth::Lite2::Error::UserDenied;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::RedirectURIMismatch;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::BadVerificationCode;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::IncorrectClientCredentials;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::AuthorizationDeclined;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::AuthorizationPending;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::SlowDown;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::CodeExpired;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::UnauthorizedClient;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::UnknownFormat;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::InvalidAssertion;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::AuthorizationExpired;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::UnsupportedSecretType;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::TokenExpired;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error::InvalidSignature;
our @ISA = qw(OAuth::Lite2::Error);

package OAuth::Lite2::Error;

1;
