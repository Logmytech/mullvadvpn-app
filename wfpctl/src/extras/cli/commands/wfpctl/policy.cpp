#include "stdafx.h"
#include "policy.h"
#include "libcommon/string.h"
#include "wfpctl/wfpctl.h"
#include <functional>

namespace commands::wfpctl
{

namespace detail
{

WfpctlSettings CreateSettings(const std::wstring &dhcp, const std::wstring &lan)
{
	WfpctlSettings s;

	s.permitDhcp = (0 == _wcsicmp(dhcp.c_str(), L"yes"));
	s.permitLan = (0 == _wcsicmp(lan.c_str(), L"yes"));

	return s;
}

WfpctlProtocol TranslateProtocol(const std::wstring &protocol)
{
	return (0 == _wcsicmp(protocol.c_str(), L"tcp") ? WfpctlProtocol::Tcp : WfpctlProtocol::Udp);
}

WfpctlRelay CreateRelay(const wchar_t *ip, const std::wstring &port, const std::wstring &protocol)
{
	WfpctlRelay r;

	r.ip = ip;
	r.port = common::string::LexicalCast<uint16_t>(port);
	r.protocol = TranslateProtocol(protocol);

	return r;
}

} // namespace detail

Policy::Policy(MessageSink messageSink)
	: m_messageSink(messageSink)
{
	m_dispatcher.addSubcommand
	(
		L"connecting",
		std::bind(&Policy::processConnecting, this, std::placeholders::_1)
	);

	m_dispatcher.addSubcommand
	(
		L"connected",
		std::bind(&Policy::processConnected, this, std::placeholders::_1)
	);

	m_dispatcher.addSubcommand
	(
		L"netblocked",
		std::bind(&Policy::processNetBlocked, this)
	);

	m_dispatcher.addSubcommand
	(
		L"reset",
		std::bind(&Policy::processReset, this)
	);
}

std::wstring Policy::name()
{
	return L"policy";
}

std::wstring Policy::description()
{
	return L"Activate and reset policies.";
}

void Policy::handleRequest(const std::vector<std::wstring> &arguments)
{
	if (arguments.empty())
	{
		throw std::runtime_error("Missing subcommand. Cannot complete request.");
	}

	auto subcommand = arguments[0];

	auto actualArguments(arguments);
	actualArguments.erase(actualArguments.begin());

	m_dispatcher.dispatch(subcommand, actualArguments);
}

void Policy::processConnecting(const KeyValuePairs &arguments)
{
	auto settings = detail::CreateSettings
	(
		GetArgumentValue(arguments, L"dhcp"),
		GetArgumentValue(arguments, L"lan")
	);

	auto r = GetArgumentValue(arguments, L"relay");

	auto relay = detail::CreateRelay
	(
		r.c_str(),
		GetArgumentValue(arguments, L"port"),
		GetArgumentValue(arguments, L"protocol")
	);

	auto success = Wfpctl_ApplyPolicyConnecting
	(
		settings,
		relay
	);

	m_messageSink((success
		? L"Successfully applied policy."
		: L"Failed to apply policy."));
}

void Policy::processConnected(const KeyValuePairs &arguments)
{
	auto settings = detail::CreateSettings
	(
		GetArgumentValue(arguments, L"dhcp"),
		GetArgumentValue(arguments, L"lan")
	);

	auto r = GetArgumentValue(arguments, L"relay");

	auto relay = detail::CreateRelay
	(
		r.c_str(),
		GetArgumentValue(arguments, L"port"),
		GetArgumentValue(arguments, L"protocol")
	);

	auto success = Wfpctl_ApplyPolicyConnected
	(
		settings,
		relay,
		GetArgumentValue(arguments, L"tunnel").c_str(),
		GetArgumentValue(arguments, L"dns").c_str()
	);

	m_messageSink((success
		? L"Successfully applied policy."
		: L"Failed to apply policy."));
}

void Policy::processNetBlocked()
{
	auto success = Wfpctl_ApplyPolicyNetBlocked();

	m_messageSink((success
		? L"Successfully applied policy."
		: L"Failed to apply policy."));
}

void Policy::processReset()
{
	auto success = Wfpctl_Reset();

	m_messageSink((success
		? L"Successfully reset policy."
		: L"Failed to reset policy."));
}

}
