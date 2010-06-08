package OAuth::Lite2::Server::EndPoint::ProtectedResource;

use strict;
use warnings;

use Plack::Request;
use Try::Tiny;

use OAuth::Lite2::Error;
use OAuth::Lite2::ParamMethods;

sub new {
    my $class = shift;
    my %args = Params::Validate::validate(@_, {
        data_handler => 1,
    });
    my $self = bless {
        data_handler => $args{data_handler},
    }, $class;
    $self;
}

sub validate {
    my ($self, $env) = @_;

    my $req = Plack::Request->new($env);

    my $parser = OAuth::Lite2::ParamMethods->get_param_parser($req);
    OAuth::Lite2::Error->throw unless $parser;

    my ($token, $params) = $parser->parse($req);
    OAuth::Lite2::Error->throw unless $token;

    my $dh = $self->{data_handler};
    my $access_token = $dh->get_access_token($token);
    OAuth::Lite2::Error::TokenNotFound->throw unless $access_token;
    OAuth::Lite2::Error::TokenExpired->throw  unless $access_token->expires_in > time;

    my $auth_info = $dh->get_auth_info_by_id($access_token->auth_id);

    if ($access_token->secret_type) {
        my $algorithm = $params->{algorithm}
            or OAuth::Lite2::Error::MissingParam->throw;

        unless ($params->{algorithm} eq $access_token->secret_type) {
            OAuth::Lite2::Error::AlgorithmMismatch->throw;
        }

        my $secret = $access_token->secret;
        unless ($secret) {
            # error
            OAuth::Lite2::Error::InvalidTokenType->throw;
        }

        my $nonce = $params->{nonce}
            or OAuth::Lite2::Error::MissingParam->throw;

        my $timestamp = $params->{timestamp}
            or OAuth::Lite2::Error::MissingParam->throw;

        $dh->check_nonce_and_timestamp(
            $auth_info->client_id, $nonce, $timestamp)
            or OAuth::Lite2::Error::InvalidTimestampAndNonce->throw;

        my $signature = $params->{signature}
            or OAuth::Lite2::Error::MissingParam->throw;

        OAuth::Lite2::Signers->verify(
            secret    => $secret,
            algorithm => $algorithm,
            method    => $req->method,
            url       => $req->request_uri,
            nonce     => $nonce,
            timestamp => $timestamp,
            signature => $signature
        ) or OAuth::Lite2::Error::InvalidSignature->throw;

    } else {

        OAuth::Lite2::Error::InsecureBearerTokenRequest->throw
            unless $req->secure;
    }

    my $client = $dh->get_client_by_id( $auth_info->client_id );

    unless ($client) {
        # error
    }

    # check $auth_info->user_id

    $env->{REMOTE_USER} = $auth_info->user_id;
    # $env->{X_OAUTH_CLIENT_ID} = $auth_info->client_id;
    # $env->{X_OAUTH_SCOPE}     = $auth_info->scope;
    # $dh->check_scope($req->path, $auth_info->scope);
}

1;

