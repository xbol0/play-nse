description = [[
Detect GraphQL api
]]

author = "xbol0"
categories = { "discovery", "safe" }
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

local shortport = require "shortport"
local stdnse = require "stdnse"
local url = require "url"
local http = require "http"
local base64 = require "base64"
local json = require "json"

local GENERAL_PATHS = {
	"/graphql", "/api", "/gql", "/query", "/mutation", "/api/graphql",
	"/graph", "/api/query", "/api/mutation", "/graphql/query", "/graphql/mutation",
	"/api0", "/api1", "/v0/graphql", "/v1/graphql", "/v2/graphql",
	"/test/graphql", "/execute", "/exec", "/api/exec", "/apigw/graphql",
	"/cgi-bin/graphql", "/cgi/graphql", "/graphql.php", "/graphiql"
}
local INTRO_QUERY = "{__schema{queryType{name}}}"
local POST_FORM = { query = INTRO_QUERY }
local USER_AGENT = [[
Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:104.0) Gecko/20100101 Firefox/104.0"
]]

portrule = shortport.port_or_service({ 80, 443 }, { "http", "https" }, "tcp", "open")

local function merge_table(...)
	local all = {}
	for _, s in ipairs(...) do
		for k, v in pairs(s) do
			all[k] = v
		end
	end
	return all
end

action = function(host, port)
	local domain = host.targetname or host.name or host.ip
	local result = { count = 0, success_list = {} }
	local headers = { ["user-agent"] = USER_AGENT }
	local pipes, auth

	auth = stdnse.get_script_args("auth-token")
	if auth ~= nil then
		stdnse.debug("auth-token = %q", auth)
		headers["authorization"] = "Bearer " .. auth
	end

	auth = stdnse.get_script_args("auth-cookie")
	if auth ~= nil then
		stdnse.debug("auth-cookie = %q", auth)
		headers["cookie"] = auth
	end

	for _, path in ipairs(GENERAL_PATHS) do
		-- local uri = base .. path
		local query = url.build_query({ query = INTRO_QUERY })

		-- General GET request
		pipes = http.pipeline_add(path .. "?" .. query, {
			header = headers
		}, pipes, "GET")

		-- GET request with base64 encoded
		query = url.build_query({ query = base64.enc(INTRO_QUERY) })
		pipes = http.pipeline_add(path .. "?" .. query, {
			header = headers
		}, pipes, "GET")

		-- General POST form-data
		pipes = http.pipeline_add(path, {
			header = merge_table(headers, {
				["content-type"] = "application/x-www-form-urlencoded",
			}),
			content = url.build_query({ query = INTRO_QUERY }),
		}, pipes, "POST")

		-- General POST json
		pipes = http.pipeline_add(path, {
			header = merge_table(headers, {
				["content-type"] = "application/json",
			}),
			content = json.generate({ query = INTRO_QUERY }),
		}, pipes, "POST")
	end

	local responses = http.pipeline_go(domain, port.number, pipes)

	stdnse.debug("count = %d", #responses)

	for i, res in ipairs(responses) do
		stdnse.debug("status = %d", res.status)
		result.count = result.count + 1

		if res.status == 200 then
			table.insert(result.success_list, pipes[i].path)
		end
	end

	return { result, header = headers }
end
