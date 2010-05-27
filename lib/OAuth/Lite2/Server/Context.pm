package OAuth::Lite2::Server::Context;

use strict;
use warnings;

use base 'Class::Accessor::Fast';

__PACKAGE__->mk_accessors(qw(request data_handler));

1;
