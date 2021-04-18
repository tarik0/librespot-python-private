# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: explicit_content_pubsub.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='explicit_content_pubsub.proto',
  package='spotify.explicit_content.proto',
  syntax='proto2',
  serialized_options=b'\n\024com.spotify.explicitH\002',
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x1d\x65xplicit_content_pubsub.proto\x12\x1espotify.explicit_content.proto\"*\n\x0cKeyValuePair\x12\x0b\n\x03key\x18\x01 \x02(\t\x12\r\n\x05value\x18\x02 \x02(\t\"S\n\x14UserAttributesUpdate\x12;\n\x05pairs\x18\x01 \x03(\x0b\x32,.spotify.explicit_content.proto.KeyValuePairB\x18\n\x14\x63om.spotify.explicitH\x02'
)




_KEYVALUEPAIR = _descriptor.Descriptor(
  name='KeyValuePair',
  full_name='spotify.explicit_content.proto.KeyValuePair',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='key', full_name='spotify.explicit_content.proto.KeyValuePair.key', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='value', full_name='spotify.explicit_content.proto.KeyValuePair.value', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=65,
  serialized_end=107,
)


_USERATTRIBUTESUPDATE = _descriptor.Descriptor(
  name='UserAttributesUpdate',
  full_name='spotify.explicit_content.proto.UserAttributesUpdate',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='pairs', full_name='spotify.explicit_content.proto.UserAttributesUpdate.pairs', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=109,
  serialized_end=192,
)

_USERATTRIBUTESUPDATE.fields_by_name['pairs'].message_type = _KEYVALUEPAIR
DESCRIPTOR.message_types_by_name['KeyValuePair'] = _KEYVALUEPAIR
DESCRIPTOR.message_types_by_name['UserAttributesUpdate'] = _USERATTRIBUTESUPDATE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

KeyValuePair = _reflection.GeneratedProtocolMessageType('KeyValuePair', (_message.Message,), {
  'DESCRIPTOR' : _KEYVALUEPAIR,
  '__module__' : 'explicit_content_pubsub_pb2'
  # @@protoc_insertion_point(class_scope:spotify.explicit_content.proto.KeyValuePair)
  })
_sym_db.RegisterMessage(KeyValuePair)

UserAttributesUpdate = _reflection.GeneratedProtocolMessageType('UserAttributesUpdate', (_message.Message,), {
  'DESCRIPTOR' : _USERATTRIBUTESUPDATE,
  '__module__' : 'explicit_content_pubsub_pb2'
  # @@protoc_insertion_point(class_scope:spotify.explicit_content.proto.UserAttributesUpdate)
  })
_sym_db.RegisterMessage(UserAttributesUpdate)


DESCRIPTOR._options = None
# @@protoc_insertion_point(module_scope)
