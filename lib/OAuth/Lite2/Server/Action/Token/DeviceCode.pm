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
    OAuth::Lite2::Server::Error::MissingParam->throw("client_id")
        unless $client_id;

    my $scope = $req->param("scope");

    my $dev_code = $dh->create_device_code(
        client_id => $client_id,
        scope     => $scope,
    );
    # XXX unless($dev_code)

    return $dev_code;
}

1;
