package TestDataHandler;

use strict;
use warnings;

use parent 'OAuth::Lite2::Server::DataHandler';

use String::Random;

use OAuth::Lite2::Server::Error;
use OAuth::Lite2::Model::AuthInfo;
use OAuth::Lite2::Model::AccessToken;

my %ID_POD = (
    auth_info    => 0,
    access_token => 0,
    user         => 0,
);

my %AUTH_INFO;
my %ACCESS_TOKEN;
my %DEVICE_CODE;
my %CLIENTS;
my %USERS;

sub clear {
    my $class = shift;
    %AUTH_INFO = ();
    %ACCESS_TOKEN = ();
    %DEVICE_CODE = ();
    %CLIENTS = ();
    %USERS = ();
}

sub gen_next_auth_info_id {
    my $class = shift;
    $ID_POD{auth_info}++;
}

sub gen_next_user_id {
    my $class = shift;
    $ID_POD{user}++;
}

sub gen_next_access_token_id {
    my $class = shift;
    $ID_POD{access_token}++;
}

sub add_client {
    my ($class, %args) = @_;
    $CLIENTS{ $args{id} } = {
        secret => $args{secret},
    };
}

sub add_user {
    my ($class, %args) = @_;
    $USERS{ $args{username} } = {
        password => $args{password},
    };
}

sub init {
    my $self = shift;
}

sub get_user_id {
    my ($self, $username, $password) = @_;
    return unless ($username && exists $USERS{$username});
    return unless ($password && $USERS{$username}{password} eq $password);
    return $username;
}

# called in folling flows:
# - web_server
# - username
# - client_credentials
# - refresh
sub get_client_user_id {
    my ($self, $client_id, $client_secret) = @_;
    return unless ($client_id && exists $CLIENTS{$client_id});
    return unless ($client_secret && $CLIENTS{$client_id}{secret} eq $client_secret);
    return $CLIENTS{$client_id};
}

# TODO needed?
sub get_client_by_id {
    my ($self, $client_id) = @_;
    return unless ($client_id && exists $CLIENTS{$client_id});
    return $CLIENTS{$client_id};
}

# called in following flows:
#   - refresh
sub get_auth_info_by_refresh_token {
    my ($self, $refresh_token) = @_;

    for my $id (keys %AUTH_INFO) {
        my $auth_info = $AUTH_INFO{$id};
        return $auth_info if $auth_info->{refresh_token} eq $refresh_token;
    }
    return;
}

sub get_auth_info_by_id {
    my ($self, $auth_id) = @_;
    return $AUTH_INFO{$auth_id};
}

# called in following flows:
#   - device_token
sub get_auth_info_by_code {
    my ($self, $device_code) = @_;
    for my $id (keys %AUTH_INFO) {
        my $auth_info = $AUTH_INFO{$id};
        return $auth_info if ($auth_info->code && $auth_info->code eq $device_code);
    }
    return;
}

sub create_or_update_auth_info {
    my ($self, %params) = @_;

    my $client_id    = $params{client_id};
    my $user_id      = $params{user_id};
    my $scope        = $params{scope};
    my $code         = $params{code};
    my $redirect_uri = $params{redirect_uri};

    my $id = ref($self)->gen_next_auth_info_id();
    my $refresh_token = sprintf q{refresh_token_%d}, $id;

    my $auth_info = OAuth::Lite2::Model::AuthInfo->new({
        id            => $id,
        client_id     => $client_id,
        user_id       => $user_id,
        scope         => $scope,
        refresh_token => $refresh_token,
    });
    $auth_info->code($code) if $code;
    $auth_info->redirect_uri($redirect_uri) if $redirect_uri;

    $AUTH_INFO{$id} = $auth_info;

    return $auth_info;
}

# called in following flows:
#   - refresh
sub create_or_update_access_token {
    my ($self, %params) = @_;

    my $auth_info = $params{auth_info};
    my $auth_id = $auth_info->id;

    my $id = ref($self)->gen_next_access_token_id();
    my $token = sprintf q{access_token_%d}, $id;

    my %attrs = (
        auth_id    => $auth_id,
        token      => $token,
        expires_in => $params{expires_in} || 3600,
        created_on => time(),
    );

    #my $secret_type = $params{secret_type};
    #if ($secret_type) {
    #    # check if $secret_type is supported
    #    OAuth::Lite2::Error::UnsupportedSecretType->throw
    #        if ($secret_type ne 'hmac-sha256');
    #    $attrs{secret_type} = $secret_type;
    #}
    #$attrs{secret} = sprintf q{access_token_secret_%d}, $id if $secret_type;

    my $access_token = OAuth::Lite2::Model::AccessToken->new(\%attrs);
    $ACCESS_TOKEN{$auth_id} = $access_token;
    return $access_token;
}

sub get_access_token {
    my ($self, $token) = @_;
    for my $auth_id ( keys %ACCESS_TOKEN ) {
        my $t = $ACCESS_TOKEN{ $auth_id };
        if ($t->token eq $token) {
            return $t;
        }
    }
    return;
}

sub validate_client {
    my ($self, $client_id, $client_secret, $type) = @_;
    return 0 unless exists $CLIENTS{ $client_id };
    my $client = $CLIENTS{ $client_id };
    return 0 unless $client->{secret} eq $client_secret;

    if ($client_id eq 'aaa') {
        if ($type eq 'basic-credentials') {
            return 1;
        } else {
            return 0;
        }
    } else {
        return 1;
    }
}

sub validate_client_by_id {
    my ($self, $client_id) = @_;
    return ($client_id ne 'malformed');
}

sub validate_user_by_id {
    my ($self, $user_id) = @_;
    return ($user_id ne 666);
}

1;

