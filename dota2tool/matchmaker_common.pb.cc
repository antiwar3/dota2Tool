// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: matchmaker_common.proto
#include "stdafx.h"
#include "matchmaker_common.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/stubs/port.h>
#include <google/protobuf/stubs/once.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// This is a temporary google only hack
#ifdef GOOGLE_PROTOBUF_ENFORCE_UNIQUENESS
#include "third_party/protobuf/version.h"
#endif
// @@protoc_insertion_point(includes)
namespace protobuf_matchmaker_5fcommon_2eproto {
const ::google::protobuf::EnumDescriptor* file_level_enum_descriptors[3];
const ::google::protobuf::uint32 TableStruct::offsets[1] = {};
static const ::google::protobuf::internal::MigrationSchema* schemas = NULL;
static const ::google::protobuf::Message* const* file_default_instances = NULL;

void protobuf_AssignDescriptors() {
  AddDescriptors();
  ::google::protobuf::MessageFactory* factory = NULL;
  AssignDescriptors(
      "matchmaker_common.proto", schemas, file_default_instances, TableStruct::offsets, factory,
      NULL, file_level_enum_descriptors, NULL);
}

void protobuf_AssignDescriptorsOnce() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &protobuf_AssignDescriptors);
}

void protobuf_RegisterTypes(const ::std::string&) GOOGLE_PROTOBUF_ATTRIBUTE_COLD;
void protobuf_RegisterTypes(const ::std::string&) {
  protobuf_AssignDescriptorsOnce();
}

void AddDescriptorsImpl() {
  InitDefaults();
  static const char descriptor[] GOOGLE_PROTOBUF_ATTRIBUTE_SECTION_VARIABLE(protodesc_cold) = {
      "\n\027matchmaker_common.proto*s\n\tMatchType\022\025"
      "\n\021MATCH_TYPE_RANKED\020\000\022\030\n\024MATCH_TYPE_COOP"
      "_BOTS\020\001\022\032\n\026MATCH_TYPE_TEAM_RANKED\020\002\022\031\n\025M"
      "ATCH_TYPE_SOLO_QUEUE\020\003*\263\001\n\021DOTABotDiffic"
      "ulty\022\032\n\026BOT_DIFFICULTY_PASSIVE\020\000\022\027\n\023BOT_"
      "DIFFICULTY_EASY\020\001\022\031\n\025BOT_DIFFICULTY_MEDI"
      "UM\020\002\022\027\n\023BOT_DIFFICULTY_HARD\020\003\022\031\n\025BOT_DIF"
      "FICULTY_UNFAIR\020\004\022\032\n\026BOT_DIFFICULTY_INVAL"
      "ID\020\005*d\n\016MatchLanguages\022\032\n\026MATCH_LANGUAGE"
      "_ENGLISH\020\001\022\032\n\026MATCH_LANGUAGE_RUSSIAN\020\002\022\032"
      "\n\026MATCH_LANGUAGE_CHINESE\020\003"
  };
  ::google::protobuf::DescriptorPool::InternalAddGeneratedFile(
      descriptor, 426);
  ::google::protobuf::MessageFactory::InternalRegisterGeneratedFile(
    "matchmaker_common.proto", &protobuf_RegisterTypes);
}

void AddDescriptors() {
  static GOOGLE_PROTOBUF_DECLARE_ONCE(once);
  ::google::protobuf::GoogleOnceInit(&once, &AddDescriptorsImpl);
}
// Force AddDescriptors() to be called at dynamic initialization time.
struct StaticDescriptorInitializer {
  StaticDescriptorInitializer() {
    AddDescriptors();
  }
} static_descriptor_initializer;
}  // namespace protobuf_matchmaker_5fcommon_2eproto
const ::google::protobuf::EnumDescriptor* MatchType_descriptor() {
  protobuf_matchmaker_5fcommon_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_matchmaker_5fcommon_2eproto::file_level_enum_descriptors[0];
}
bool MatchType_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
    case 2:
    case 3:
      return true;
    default:
      return false;
  }
}

const ::google::protobuf::EnumDescriptor* DOTABotDifficulty_descriptor() {
  protobuf_matchmaker_5fcommon_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_matchmaker_5fcommon_2eproto::file_level_enum_descriptors[1];
}
bool DOTABotDifficulty_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 4:
    case 5:
      return true;
    default:
      return false;
  }
}

const ::google::protobuf::EnumDescriptor* MatchLanguages_descriptor() {
  protobuf_matchmaker_5fcommon_2eproto::protobuf_AssignDescriptorsOnce();
  return protobuf_matchmaker_5fcommon_2eproto::file_level_enum_descriptors[2];
}
bool MatchLanguages_IsValid(int value) {
  switch (value) {
    case 1:
    case 2:
    case 3:
      return true;
    default:
      return false;
  }
}


// @@protoc_insertion_point(namespace_scope)

// @@protoc_insertion_point(global_scope)
