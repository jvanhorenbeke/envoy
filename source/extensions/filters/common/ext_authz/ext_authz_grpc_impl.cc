#include "extensions/filters/common/ext_authz/ext_authz_grpc_impl.h"

#include "common/common/assert.h"
#include "common/grpc/async_client_impl.h"
#include "common/http/headers.h"
#include "common/http/utility.h"
#include "common/network/utility.h"
#include "common/protobuf/protobuf.h"

namespace Envoy {
namespace Extensions {
namespace Filters {
namespace Common {
namespace ExtAuthz {

// Values used for selecting service paths.
// TODO(gsagula): keep only V2 when V2Alpha gets deprecated.
constexpr char V2[] = "envoy.service.auth.v2.Authorization.Check";
constexpr char V2alpha[] = "envoy.service.auth.v2alpha.Authorization.Check";

GrpcClientImpl::GrpcClientImpl(Grpc::RawAsyncClientPtr&& async_client,
                               const absl::optional<std::chrono::milliseconds>& timeout,
                               bool use_alpha)
    : service_method_(getMethodDescriptor(use_alpha)), async_client_(std::move(async_client)),
      timeout_(timeout) {}

GrpcClientImpl::~GrpcClientImpl() { ASSERT(!callbacks_); }

void GrpcClientImpl::cancel() {
  ASSERT(callbacks_ != nullptr);
  request_->cancel();
  callbacks_ = nullptr;
}

void GrpcClientImpl::check(RequestCallbacks& callbacks,
                           const envoy::service::auth::v2::CheckRequest& request,
                           Tracing::Span& parent_span) {
  ASSERT(callbacks_ == nullptr);
  callbacks_ = &callbacks;
  ENVOY_LOG(debug, "[JELLE] ext_authz filter inside GrpcClientImpl::check");
  request_ = async_client_->send(service_method_, request, *this, parent_span,
                                 Http::AsyncClient::RequestOptions().setTimeout(timeout_));
  ENVOY_LOG(debug, "[JELLE] ext_authz filter end of GrpcClientImpl::check");
}

void GrpcClientImpl::onSuccess(std::unique_ptr<envoy::service::auth::v2::CheckResponse>&& response,
                               Tracing::Span& span) {
  ENVOY_LOG(debug, "[JELLE] ext_authz filter inside GrpcClientImpl::onSuccess");

  ResponsePtr authz_response = std::make_unique<Response>(Response{});
  if (response->status().code() == Grpc::Status::WellKnownGrpcStatus::Ok) {
    span.setTag(TracingConstants::get().TraceStatus, TracingConstants::get().TraceOk);
    authz_response->status = CheckStatus::OK;
      ENVOY_LOG(debug, "[JELLE] ext_authz filter WellKnownGrpcStatus::OK");
    if (response->has_ok_response()) {
      ENVOY_LOG(debug, "[JELLE] ext_authz filter has ok response");
      toAuthzResponseHeader(authz_response, response->ok_response().headers());
    }
  } else {
    span.setTag(TracingConstants::get().TraceStatus, TracingConstants::get().TraceUnauthz);
    authz_response->status = CheckStatus::Denied;
    if (response->has_denied_response()) {
      toAuthzResponseHeader(authz_response, response->denied_response().headers());
      authz_response->status_code =
          static_cast<Http::Code>(response->denied_response().status().code());
      authz_response->body = response->denied_response().body();
    } else {
      authz_response->status_code = Http::Code::Forbidden;
    }
  }

  callbacks_->onComplete(std::move(authz_response));
  callbacks_ = nullptr;
}

void GrpcClientImpl::onFailure(Grpc::Status::GrpcStatus status, const std::string&,
                               Tracing::Span&) {
  ENVOY_LOG(debug, "[JELLE] before assert, ext_authz filter inside GrpcClientImpl::onFailure status=" + std::to_string(status));
  ASSERT(status != Grpc::Status::WellKnownGrpcStatus::Ok);
  ENVOY_LOG(debug, "[JELLE] after assert, ext_authz filter inside GrpcClientImpl::onFailure status=" + std::to_string(status));
  Response response{};
  response.status = CheckStatus::Error;
  response.status_code = Http::Code::Forbidden;
  callbacks_->onComplete(std::make_unique<Response>(response));
  callbacks_ = nullptr;
}

void GrpcClientImpl::toAuthzResponseHeader(
    ResponsePtr& response,
    const Protobuf::RepeatedPtrField<envoy::api::v2::core::HeaderValueOption>& headers) {
  for (const auto& header : headers) {
    if (header.append().value()) {
      response->headers_to_append.emplace_back(Http::LowerCaseString(header.header().key()),
                                               header.header().value());
    } else {
      response->headers_to_add.emplace_back(Http::LowerCaseString(header.header().key()),
                                            header.header().value());
    }
  }
}

const Protobuf::MethodDescriptor& GrpcClientImpl::getMethodDescriptor(bool use_alpha) {
  const auto* descriptor =
      use_alpha ? Protobuf::DescriptorPool::generated_pool()->FindMethodByName(V2alpha)
                : Protobuf::DescriptorPool::generated_pool()->FindMethodByName(V2);
  ASSERT(descriptor != nullptr);
  return *descriptor;
}

} // namespace ExtAuthz
} // namespace Common
} // namespace Filters
} // namespace Extensions
} // namespace Envoy
