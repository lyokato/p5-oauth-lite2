package OAuth::Lite2::Server::Action::Token::Refresh;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Action::Token';
use OAuth::Lite2::Error;

sub handle_request {

    my ($self, $ctx) = @_;

    my $dh = $ctx->data_handler;

    my $client_id = $ctx->req->param("client_id");
    OAuth::Lite2::Server::Error::MissingParam->throw("'client_id' not found")
        unless $client_id;

    my $client_secret = $ctx->req->param("client_secret");
    OAuth::Lite2::Server::Error::MissingParam->throw("'client_secret' not found")
        unless $client_secret;

    my $refresh_token = $ctx->req->param("refresh_token");
    OAuth::Lite2::Server::Error::MissingParam->throw("'refresh_token' not found")
        unless $refresh_token;

    my $secret_type = $ctx->req->param("secret_type");

    # XXX validate
    my $client = $dh->get_client_user(
        client_id     => $client_id,
        client_secret => $client_secret,
    );

    my $auth_info = $dh->get_auth_info_by_refresh_token($refresh_token);

    my $access_token = $dh->create_or_update_access_token(
        auth_id     => $auth_info->id,
        secret_type => $secret_type,
    );
}

1;

