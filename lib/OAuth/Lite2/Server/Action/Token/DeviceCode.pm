package OAuth::Lite2::Server::Action::Token::DeviceCode;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::Action::Token';
use OAuth::Lite2::Error;

sub handle_request {
    my ($self, $ctx) = @_;

    my $dh  = $ctx->data_handler;
    my $req = $ctx->request;

    my $client_id = $req->param("client_id");
    OAuth::Lite2::Error::Server::MissingParam->throw(
        message => "'client_id' not found"
    ) unless $client_id;

    $dh->validate_client_by_id($client_id)
        or OAuth::Lite2::Error::Server::InvalidClient->throw;

    my $scope = $req->param("scope");

    my $dev_code = $dh->create_or_update_device_code(
        client_id => $client_id,
        scope     => $scope,
    );
    # XXX unless($dev_code)

    my $res = {
        code             => $dev_code->code,
        user_code        => $dev_code->user_code,
        verification_uri => $dev_code->verification_uri,
    };
    $res->{expires_in} = $dev_code->expires_in if $dev_code->expires_in;
    $res->{interval} = $dev_code->interval if $dev_code->interval;

    return $res;
}

1;
