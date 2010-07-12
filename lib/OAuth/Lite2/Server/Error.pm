package OAuth::Lite2::Server::Error;

use strict;
use warnings;

use overload
    q{""}    => sub { sprintf q{%s: %s}, $_[0]->type, $_[0]->description },
    fallback => 1;

=head1 NAME

OAuth::Lite2::Server::Error - OAuth 2.0 server errors

=head1 SYNOPSIS

    # At End-User Endpoint

    try {

        if ($something_wrong) {

            OAuth::Lite2::Server::Error::InvalidRequest->throw(
                description => q{Something wrong},
                # uri       => q{http://example.org/error/description},
                # state     => q{foo},
            );
        }

    } catch {

        if ($_->isa("OAuth::Lite2::Server::Error")) {

            my $uri = URI->new( $client_callback_uri );

            my %error_params = ( error => $_->type );
            $error_params{error_description} = $_->description if $_->description;
            $error_params{uri} = $_->uri if $_->uri;
            $error_params{state} = $_->state if $_->state;

            $uri->query_form(%error_params);

            $your_app->redirect( $uri->as_string );

        } else {

            # Internal Server Error

        }
    };


    # At token-endpoint

    try {


    } catch {

        if ($_->isa("OAuth::Lite2::Server::Error")) {

            my %error_params = ( error => $_->type );
            $error_params{error_description} = $_->description if $_->description;
            $error_params{error_uri} = $_->uri if $_->uri;
            $error_params{scope} = $_->scope if $_->scope;

            $req->new_response($_->code,
                [ "Content-Type" => $formatter->type, "Cache-Control" => "no-store" ],
                [ $formatter->format(\%error_params) ],
            );

        } else {

            # rethrow
            die $_;

        }

    };

=head1 DESCRIPTION

OAuth 2.0 error classes.

See
L<http://tools.ietf.org/html/draft-ietf-oauth-v2-09#section-3.2>,
L<http://tools.ietf.org/html/draft-ietf-oauth-v2-09#section-4.3>,
L<http://tools.ietf.org/html/draft-ietf-oauth-v2-09#section-5.2>

=head1 METHODS

=head1 ERRORS

=over 4

=item OAuth::Lite2::Server::Error::AccessDenied

=item OAuth::Lite2::Server::Error::ExpiredToken

=item OAuth::Lite2::Server::Error::InvalidRequest

=item OAuth::Lite2::Server::Error::InvalidToken

=item OAuth::Lite2::Server::Error::InvalidClient

=item OAuth::Lite2::Server::Error::InvalidGrant

=item OAuth::Lite2::Server::Error::InvalidScope

=item OAuth::Lite2::Server::Error::RedirectURIMismatch

=item OAuth::Lite2::Server::Error::UnauthorizedClient

=item OAuth::Lite2::Server::Error::UnsupportedGrantType

=item OAuth::Lite2::Server::Error::UnsupportedResourceType

=back

=cut

sub new {
    my ($class, %args) = @_;
    bless {
        description => $args{description} || '',
        uri         => $args{uri}         || '',
        state       => $args{state}       || '',
        code        => $args{code}        || 400,
    }, $class;
}

sub throw {
    my ($class, %args) = @_;
    die $class->new(%args);
}

sub code        { $_[0]->{code}         }
sub type        { die "abstract method" }
sub description { $_[0]->{description}  }
sub uri         { $_[0]->{uri}          }
sub state       { $_[0]->{state}        }

# OAuth Server Error
package OAuth::Lite2::Server::Error::InvalidRequest;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub type { "invalid_request" }

package OAuth::Lite2::Server::Error::InvalidClient;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "invalid_client" }

package OAuth::Lite2::Server::Error::UnauthorizedClient;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "unauthorized_client" }

package OAuth::Lite2::Server::Error::RedirectURIMismatch;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "redirect_uri_mismatch" }

package OAuth::Lite2::Server::Error::AccessDenied;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "access_denied" }

package OAuth::Lite2::Server::Error::UnsupportedResourceType;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub type { "unsupported_resource_type" }

package OAuth::Lite2::Server::Error::InvalidGrant;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "invalid_grant" }

package OAuth::Lite2::Server::Error::UnsupportedGrantType;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub type { "unsupported_grant_type" }

package OAuth::Lite2::Server::Error::InvalidScope;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "invalid_scope" }

package OAuth::Lite2::Server::Error::InvalidToken;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "invalid_token" }

package OAuth::Lite2::Server::Error::ExpiredToken;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "expired_token" }

package OAuth::Lite2::Server::Error::InefficientScope;
our @ISA = qw(OAuth::Lite2::Server::Error);
sub code { 401 }
sub type { "inefficient_scope" }

package OAuth::Lite2::Server::Error;

1;
