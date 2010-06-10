package OAuth::Lite2::Client::Code;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    code
    user_code
    verification_uri
    expires_in
    interval
));

1;
