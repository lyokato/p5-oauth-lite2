package OAuth::Lite2::Client::TokenResponseParser;

use strict;
use warnings;

use Try::Tiny;
use OAuth::Lite2::Formatters;
use OAuth::Lite2::Error;
use OAuth::Lite2::Client::Token;

sub new {
    bless {}, $_[0];
}

sub parse {
    my ($self, $http_res) = @_;

    my $formatter =
        OAuth::Lite2::Formatters->get_formatter_by_type(
            $http_res->content_type);

    my $token;

    if ($http_res->is_success) {

        OAuth::Lite2::Error::InvalidFormat->throw(
            message => sprintf(q{Invalid content type "%s"},
                $http_res->content_type||'')
        ) unless $formatter;

        my $http_result = $formatter->parse($http_res->content);

        OAuth::Lite2::Error::InvalidResponse->throw(
            message => sprintf("Response doesn't include 'access_token'")
        ) unless exists $http_result->{access_token};

        $token = OAuth::Lite2::Client::Token->new($http_result);

    } else {

        my $errmsg = $http_res->content || $http_res->status_line;
        if ($formatter && $http_res->content) {
            try {
                my $http_result = $formatter->parse($http_res->content);
                $errmsg = $http_result->{error}
                    if exists $http_result->{error};
            } catch { return };
        }
        OAuth::Lite2::Error::InvalidResponse->throw( message => $errmsg );
    }
    return $token;
}


1;
