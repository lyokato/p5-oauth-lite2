package OAuth::Lite2::Model::DeviceCode;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(
    scope
    client_id
    created_on

    code
    user_code
    expires_in

    verification_url
    interval
));

1;
