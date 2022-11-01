defmodule OpenIDConnect.Worker do
  use GenServer

  @moduledoc """
  Worker module for OpenID Connect

  This worker will store and periodically update each provider's documents and JWKs according to the lifetimes
  """

  @default_tenant_placeholder ":tenant"
  @refresh_time 60 * 60 * 1000

  def start_link(provider_configs, name \\ :openid_connect) do
    GenServer.start_link(__MODULE__, provider_configs, name: name)
  end

  def init(:ignore) do
    :ignore
  end

  def init(provider_configs) do
    {:ok, %{}, {:continue, {:init, provider_configs}}}
  end

  def handle_continue({:init, provider_configs}, _state) do
    state =
      Enum.into(provider_configs, %{}, fn {provider, config} ->
        tenants = get_initial_tenants(config)
        {documents, timer_ref} = update_documents(provider, config, tenants, %{})

        provider_data = %{
          config: config,
          documents: documents,
          tenants: tenants,
          timer_ref: timer_ref
        }

        {provider, provider_data}
      end)

    {:noreply, state}
  end

  def handle_call({:discovery_document, provider}, _from, state) do
    discovery_document = get_in(state, [provider, :documents, :discovery_document])
    {:reply, discovery_document, state}
  end

  def handle_call({:jwk, provider, tenant}, _from, state) do
    {jwk, state} = fetch_jwk(provider, tenant, state)
    {:reply, jwk, state}
  end

  def handle_call({:config, provider}, _from, state) do
    config = get_in(state, [provider, :config])
    {:reply, config, state}
  end

  def handle_info({:update_documents, provider}, state) do
    %{config: config, tenants: tenants, documents: documents} =
      provider_data = Map.get(state, provider)

    {documents, timer_ref} = update_documents(provider, config, tenants, documents)

    state =
      Map.put(state, provider, %{provider_data | documents: documents, timer_ref: timer_ref})

    {:noreply, state}
  end

  defp get_initial_tenants(config) do
    tenants = get_in(config, [:multi_tenant, :tenants]) || []
    dynamic? = get_in(config, [:multi_tenant, :dynamic]) || false

    cond do
      length(tenants) > 0 -> tenants
      dynamic? -> tenants
      true -> [:default]
    end
  end

  defp update_documents(provider, config, tenants, documents) do
    uri_builder = get_uri_builder(config)
    {documents, refresh_time} = update_all_documents(documents, tenants, uri_builder)
    timer_ref = Process.send_after(self(), {:update_documents, provider}, refresh_time)
    {documents, timer_ref}
  end

  defp get_uri_builder(config) do
    discovery_document_uri = Keyword.get(config, :discovery_document_uri)

    case get_in(config, [:multi_tenant, :dynamic]) do
      true -> tenant_uri_builder(config)
      _ -> fn _ -> discovery_document_uri end
    end
  end

  defp tenant_uri_builder(config) do
    placeholder = get_in(config, [:multi_tenant, :placeholder]) || @default_tenant_placeholder
    discovery_document_uri = Keyword.get(config, :discovery_document_uri)
    [uri_part1, uri_part2] = String.split(discovery_document_uri, placeholder, parts: 2)
    fn tenant -> "#{uri_part1}#{tenant}#{uri_part2}" end
  end

  defp update_all_documents(documents, tenants, uri_builder) do
    Enum.reduce(tenants, {documents, @refresh_time}, fn tenant,
                                                        {documents_acc, refresh_time_acc} ->
      discovery_document_uri = uri_builder.(tenant)

      IO.inspect(discovery_document_uri, label: :discovery_document_uri)

      case OpenIDConnect.update_documents(discovery_document_uri) do
        {:ok, %{remaining_lifetime: remaining_lifetime} = documents} ->
          refresh_time = time_until_next_refresh(remaining_lifetime)

          next_refresh_time =
            if refresh_time < refresh_time_acc, do: refresh_time, else: refresh_time_acc

          {Map.put(documents_acc, tenant, documents), next_refresh_time}

        error ->
          {Map.put(documents_acc, tenant, error), refresh_time_acc}
      end
    end)
  end

  defp time_until_next_refresh(nil), do: @refresh_time

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds > 0,
    do: :timer.seconds(time_in_seconds)

  defp time_until_next_refresh(time_in_seconds) when time_in_seconds <= 0, do: 0

  defp fetch_jwk(provider, tenant, state) do
    provider_data = Map.get(state, provider)

    case get_in(provider_data, [:documents, tenant, :jwk]) do
      nil ->
        cond do
          tenant not in get_in(provider_data, [:tenants]) and
              get_in(provider_data, [:config, :multi_tenant, :dynamic]) ->
            provider_data = add_tenant(provider, tenant, provider_data)
            jwk = get_in(provider_data, [:documents, tenant, :jwk])
            new_state = Map.put(state, provider, provider_data)
            {jwk, new_state}

          true ->
            {nil, state}
        end

      jwk ->
        {jwk, state}
    end
  end

  defp add_tenant(provider, tenant, provider_data) do
    %{config: config, documents: documents, tenants: tenants, timer_ref: timer_ref} =
      provider_data

    Process.cancel_timer(timer_ref)
    {documents, timer_ref} = update_documents(provider, config, [tenant], documents)
    %{provider_data | documents: documents, tenants: [tenant | tenants], timer_ref: timer_ref}
  end
end
