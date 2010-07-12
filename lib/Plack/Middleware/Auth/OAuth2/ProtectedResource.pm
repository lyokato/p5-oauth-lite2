package Plack::Middleware::Auth::OAuth2::ProtectedResource;

use strict;
use warnings;

use parent 'Plack::Middleware';

use Plack::Request;
use Plack::Util::Accessor qw(realm data_handler);
use Try::Tiny;

use OAuth::Lite2::Server::Error;
use OAuth::Lite2::ParamMethods;

sub call {
    my ($self, $env) = @_;

    my $error_res = try {

        my $req = Plack::Request->new($env);

        # after draft-v6, signature is not required, so always each connection
        # should be under TLS.
        warn "insecure barere token request" unless $req->secure;

        my $parser = OAuth::Lite2::ParamMethods->get_param_parser($req)
            or OAuth::Lite2::Server::Error::InvalidRequest->throw;

        # after draft-v6, $params aren't required.
        my ($token, $params) = $parser->parse($req);
        OAuth::Lite2::Server::Error::InvalidRequest->throw unless $token;

        my $dh = $self->{data_handler}->new;

        my $access_token = $dh->get_access_token($token);

        OAuth::Lite2::Server::Error::InvalidToken->throw
            unless $access_token;

        OAuth::Lite2::Server::Error::ExpiredToken->throw
            unless ($access_token->created_on + $access_token->expires_in > time());

        my $auth_info = $dh->get_auth_info_by_id($access_token->auth_id);
        # TODO validate auth_info

        $dh->validate_client_by_id($auth_info->client_id)
            or OAuth::Lite2::Server::Error::InvalidToken->throw;

        $dh->validate_user_by_id($auth_info->user_id)
            or OAuth::Lite2::Server::Error::InvalidToken->throw;

        $env->{REMOTE_USER}    = $auth_info->user_id;
        $env->{X_OAUTH_CLIENT} = $auth_info->client_id;
        $env->{X_OAUTH_SCOPE}  = $auth_info->scope;

        return;

    } catch {

        if ($_->isa("OAuth::Lite2::Server::Error")) {

            my @params;
            push(@params, sprintf(q{realm='%s'}, $self->{realm}))
                if $self->{realm};
            push(@params, sprintf(q{error='%s'}, $_->type));
            push(@params, sprintf(q{error-desc='%s'}, $_->description))
                if $_->description;
            push(@params, sprintf(q{error-uri='%s'}, $_->uri))
                if $_->uri;
            # push(@params, sprintf(q{scope='%s'}, $_->scope))
            #     if $_->scope;

            return [ $_->code, [ "WWW-Authenticate" =>
                "OAuth " . join(', ', @params) ], [  ] ];

        } else {

            # rethrow
            die $_;

        }

    };

    return $error_res || $self->app->($env);
}

1;
