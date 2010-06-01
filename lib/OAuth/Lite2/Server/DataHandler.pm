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
    my ($self, $flow, $client_id, $client_name) = @_;
    OAuth::Lite2::Error::AbstractMethod->throw;
    return 1;
}

sub get_user {
    my ($self, %args) = @_;

    Params::Validate::validate(@_, {
        username => 1,
        password => 1,
    });

    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub get_client_user {
    my ($self, %args) = @_;

    Params::Validate::validate(@_, {
        client_id     => 1,
        client_secret => 1,
    });
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
        user        => 1,
        scope       => 1,
    });
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub create_or_update_access_token {
    my ($self, %args) = @_;
    Params::Validate::validate(@_, {
        auth_id     => 1,
        secret_type => 1,
    });
    OAuth::Lite2::Error::AbstractMethod->throw;
}

sub create_device_code {
    my ($self, %args) = @_;
    Params::Validate::validate(@_, {
        client_id   => 1,
        scope       => 1,
    });
}

1;
