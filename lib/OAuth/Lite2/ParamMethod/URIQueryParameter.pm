package OAuth::Lite2::ParamMethod::URIQueryParameter;

use strict;
use warnings;

use parent 'OAuth::Lite2::ParamMethod';

sub match {
    my ($self, $req) = @_;
    return $req->query_parameters->{oauth_token};
}

sub parse {
    my ($self, $req) = @_;
    my $params = $req->query_parameters;
    my $token = $params->{oauth_token};
    $params->remove('oauth_token');
    return ($token, $params);
}

1;
