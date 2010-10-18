package OAuth::Lite2::Server::GrantHandlers;

use strict;
use warnings;

use OAuth::Lite2::Server::GrantHandler::AuthorizationCode;
use OAuth::Lite2::Server::GrantHandler::Password;
use OAuth::Lite2::Server::GrantHandler::RefreshToken;

my %HANDLERS;

sub add_handler {
    my ($class, $type, $handler) = @_;
    $HANDLERS{$type} = $handler;
}

__PACKAGE__->add_handler( 'authorization-code' =>
    OAuth::Lite2::Server::GrantHandler::AuthorizationCode->new );
__PACKAGE__->add_handler( 'password' =>
    OAuth::Lite2::Server::GrantHandler::Password->new );
__PACKAGE__->add_handler( 'refresh-token' =>
    OAuth::Lite2::Server::GrantHandler::RefreshToken->new );

#__PACKAGE__->add_handler( 'assertion' => );
#__PACKAGE__->add_handler( 'none' => );

sub get_handler {
    my ($class, $type) = @_;
    return $HANDLERS{$type};
}

=head1 NAME

OAuth::Lite2::Server::GrantHandlers - store of handlers for each grant_type.

=head1 SYNOPSIS

    my $handler = OAuth::Lite2::Server::GrantHandlers->get_handler( $grant_type );
    $handler->handle_request( $ctx );

=head1 DESCRIPTION

store of handlers for each grant_type.

=head1 METHODS

=head2 add_handler( $grant_type, $handler )

=head2 get_handler( $grant_type )

=head1 SEE ALSO

L<OAuth::Lite2::Server::GrantHandler>
L<OAuth::Lite2::Server::GrantHandler::AuthorizationCode>
L<OAuth::Lite2::Server::GrantHandler::Password>
L<OAuth::Lite2::Server::GrantHandler::RefreshToken>

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;

