package OAuth::Lite2::Client::Token;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    access_token
    expires_in
    refresh_token
    access_token_secret
    scope
));

1;
