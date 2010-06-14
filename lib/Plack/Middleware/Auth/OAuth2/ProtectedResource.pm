package Plack::Middleware::Auth::OAuth2::ProtectedResource;

use strict;
use warnings;

use parent 'Plack::Middleware';

use Plack::Request;
use Plack::Util::Accessor qw(realm data_handler);
use Try::Tiny;

use OAuth::Lite2::Error;
use OAuth::Lite2::ParamMethods;

sub call {
    my ($self, $env) = @_;

    my $error_res = try {

        my $req = Plack::Request->new($env);

        # from draft-v6, signature is not required, so always each connection
        # should be under TLS.
        OAuth::Lite2::Error::InsecureBearerTokenRequest->throw
            unless $req->secure;

        my $parser = OAuth::Lite2::ParamMethods->get_param_parser($req)
            or OAuth::Lite2::Error->throw( message => q{This is not OAuth request.} );

        # from draft-v6, params aren't required.
        my ($token, $params) = $parser->parse($req);
        OAuth::Lite2::Error->throw( message => q{This is not OAuth request.} )
            unless $token;

        my $dh = $self->{data_handler}->new;

        my $access_token = $dh->get_access_token($token);

        OAuth::Lite2::Error::TokenNotFound->throw
            unless $access_token;

        OAuth::Lite2::Error::TokenExpired->throw
            unless ($access_token->created_on + $access_token->expires_in > time());

        my $auth_info = $dh->get_auth_info_by_id($access_token->auth_id);
        # TODO validate auth_info

        $dh->validate_client_by_id($auth_info->client_id)
            or OAuth::Lite2::Server::Error::InvalidClient->throw;

        $dh->validate_user_by_id($auth_info->user_id)
            or OAuth::Lite2::Server::Error::InvalidUser->throw;

        $env->{REMOTE_USER}    = $auth_info->user_id;
        $env->{X_OAUTH_CLIENT} = $auth_info->client_id;
        $env->{X_OAUTH_SCOPE}  = $auth_info->scope;

        return;

    } catch {

        if ($_->isa("OAuth::Lite2::Error")) {

            return [ 401, [ "WWW-Authenticate" =>
                sprintf("Token error='%s'", $_->message ) ], [  ] ];

        } else {

            # Internal Server Error
            return [ 500, [ ], [  ] ];

        }

    };

    return $error_res || $self->app->($env);
}

1;
