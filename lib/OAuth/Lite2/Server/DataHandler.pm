package OAuth::Lite2::Server::DataHandler;

use strict;
use warnings;

use Params::Validate;
use OAuth::Lite2::Error;

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

sub validate_client_action {
    my ($self, $flow, $client_id) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
    return 1;
}

sub validate_client_by_id {
    my ($self, $client_id) = @_;
    1;
}

sub validate_user_by_id {
    my ($self, $user_id) = @_;
    1;
}

sub get_user_id {
    my ($self, $username, $password) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub get_client_user_id {
    my ($self, $client_id, $client_secret) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub get_access_token {
    my ($self, $token) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub get_auth_info_by_id {
    my ($self, $id) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub get_auth_info_by_code {
    my ($self, $code) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub get_auth_info_by_refresh_token {
    my ($self, $refresh_token) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub create_or_update_auth_info {
    my ($self, %args) = @_;
    Params::Validate::validate(@_, {
        client_id   => 1,
        user_id     => 1,
        scope       => 1,
    });
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub create_or_update_access_token {
    my ($self, %args) = @_;
    Params::Validate::validate(@_, {
        auth_info   => 1,
        secret_type => 1,
    });
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub create_or_update_device_code {
    my ($self, %args) = @_;
    Params::Validate::validate(@_, {
        client_id   => 1,
        scope       => 1,
    });
    OAuth::Lite2::Error::AbstractMethod->throw;
}

1;
