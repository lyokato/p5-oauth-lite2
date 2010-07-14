package OAuth::Lite2::Server::GrantHandler::Password;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::GrantHandler';
use OAuth::Lite2::Server::Error;

sub handle_request {
    my ($self, $ctx) = @_;

    my $req = $ctx->request;
    my $dh  = $ctx->data_handler;

    my $client_id = $req->param("client_id");

    my $username = $req->param("username");
    OAuth::Lite2::Server::Error::InvalidRequest->throw(
        description => "'username' not found"
    ) unless $username;

    my $password = $req->param("password")
        or OAuth::Lite2::Server::Error::InvalidRequest->throw(
            description => "'password' not found"
        );

    my $user_id = $dh->get_user_id($username, $password)
        or OAuth::Lite2::Server::Error::InvalidGrant->throw;

    my $scope = $req->param("scope");

    my $auth_info = $dh->create_or_update_auth_info(
        client_id => $client_id,
        user_id   => $user_id,
        scope     => $scope,
    );
    # TODO check $auth_info

    my $access_token = $dh->create_or_update_access_token(
        auth_info => $auth_info,
    );
    # TODO check $access_token

    my $res = {
        access_token => $access_token->token,
    };
    $res->{expires_in} = $access_token->expires_in
        if $access_token->expires_in;
    $res->{refresh_token} = $auth_info->refresh_token
        if $auth_info->refresh_token;
    $res->{scope} = $auth_info->scope
        if $auth_info->scope;

    return $res;
}

=head1 NAME

OAuth::Lite2::Server::GrantHandler::Password - handler for 'password' grant_type request

=head1 SYNOPSIS

    my $handler = OAuth::Lite2::Server::GrantHandler::Password->new;
    my $res = $handler->handle_request( $ctx );

=head1 DESCRIPTION

handler for 'password' grant_type request.

=head1 METHODS

=head2 handle_request( $req )

See L<OAuth::Lite2::Server::GrantHandler> document.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
