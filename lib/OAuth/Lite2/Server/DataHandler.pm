package OAuth::Lite2::Server::DataHandler;

use strict;
use warnings;

use Params::Validate;
use OAuth::Lite2::Server::Error;

sub new {
    my $class = shift;
    my $self = bless { @_ }, $class;
    $self->init;
    $self;
}

sub init {
    my $self = shift;
    # template method
}

sub validate_client {
    my ($self, $client_id, $client_secret, $grant_type) = @_;
    die "abstract method";
    return 1;
}

sub get_user_id {
    my ($self, $username, $password) = @_;
    die "abstract method";
}

sub create_or_update_auth_info {
    my ($self, %args) = @_;
    Params::Validate::validate(@_, {
        client_id   => 1,
        user_id     => 1,
        scope       => { optional => 1 },
    });
    die "abstract method";
}

sub create_or_update_access_token {
    my ($self, %args) = @_;
    Params::Validate::validate(@_, {
        auth_info   => 1,
        # secret_type => 1,
    });
    die "abstract method";
}

sub get_auth_info_by_code {
    my ($self, $code) = @_;
    die "abstract method";
}

sub get_auth_info_by_refresh_token {
    my ($self, $refresh_token) = @_;
    die "abstract method";
}

sub get_client_user_id {
    my ($self, $client_id) = @_;
    die "abstract method";
}

sub validate_client_by_id {
    my ($self, $client_id) = @_;
    1;
}

sub validate_user_by_id {
    my ($self, $user_id) = @_;
    1;
}

sub get_access_token {
    my ($self, $token) = @_;
    die "abstract method";
}

sub get_auth_info_by_id {
    my ($self, $id) = @_;
    die "abstract method";
}

=head1 NAME

OAuth::Lite2::Server::DataHandler - Base class that specifies interface for data handler for your service.

=head1 SYNOPSIS

=head1 DESCRIPTION

This specifies interface to handle data stored on your application.
You have to inherit this, and implements subroutines according to the interface contract.
This is proxy or adapter that connects OAuth::Lite2 library to your service.

=head1 METHODS

=head2 init

If your subclass need some initiation, implement in this method.

=head1 INTERFACES

=head2 validate_client( $client_id, $client_secret, $grant_type )

This interface is used on Token Endpoint.
In spite of grant_type, all the time this method is called.

You can check here the client_id is valid? and client credentials is not invalid?
And the client is allowed to use this grant_type?

If it's OK, return 1. Return 0 if not.

=head2 get_user_id( $username, $password )

This interface is used on Token Endpoint, when requested grant_type is 'password'.
Username and password is passed. You check if the credentials is valid or not.
And if it's OK, return the user's identifier that is managed on your service.

=head2 create_or_update_auth_info( %params )

Create and save new authorization info.
Should return L<OAuth::Lite2::Model::AuthInfo> object.

=head2 create_or_update_access_token( %params )

Create and save new access token.
Should return L<OAuth::Lite2::Model::AccessToken> object.

=head2 get_auth_info_by_code( $code )

This interface is used when client obtains access_token using authorization-code
that would be issued by server with user's authorization.
For instance, Web Server Profile requires this interface.

Should return L<OAuth::Lite2::Model::AuthInfo> object.

=head2 get_auth_info_by_refresh_token( $refresh_token )

This interface is used when refresh access_token.

Should return L<OAuth::Lite2::Model::AuthInfo> object.

=head2 get_access_token( $token )

This interface is used on protected resource endpoint.
See L<Plack::Middleware::Auth::OAuth2::ProtectedResource>.
get attributes that belongs to the token that is included
HTTP request accesses to the endpoint.
Should return L<OAuth::Lite2::Model::AccessToken> object.

=head2 get_auth_info_by_id( $auth_id )

This interface is used on protected resource endpoint.
See L<Plack::Middleware::Auth::OAuth2::ProtectedResource>.
This method is called after get_access_token method.
get authorization-info that is related to the $auth_id
that has relation with the access token.

Should return L<OAuth::Lite2::Model::AuthInfo> object.

=head2 validate_client_by_id( $client_id )

This fook is called on protected resource endpoint.
See L<Plack::Middleware::Auth::OAuth2::ProtectedResource>.

After checking if token is valid, furthermore you can check
if the client related the token is valid in this method.

If passed client_id is invalid for some reason, return 0.
If OK, return 1.

=head2 validate_user_by_id( $user_id )

This fook is called on protected resource endpoint.
See L<Plack::Middleware::Auth::OAuth2::ProtectedResource>.

After checking if token is valid, furthermore you can check
if the user related the token is valid in this method.

If passed user_id is invalid for some reason, return 0.
If OK, return 1.

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
