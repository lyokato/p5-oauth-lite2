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
    my ($self, $client_id, $client_secret) = @_;
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

=head1 AUTHOR

Lyo Kato, E<lt>lyo.kato@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2010 by Lyo Kato

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut

1;
