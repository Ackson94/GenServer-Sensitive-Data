defmodule SecurityTokenManager do
  use GenServer
  @derive {Inspect, except: [:expires_at]}
  defstruct [:access_key, :secret_access, :security_token, :expires_at]

  @security_token_size 20
  @miliseconds_in_second 1000
  # 15 minutes
  @expires_in_seconds 60 * 15

  def start_link do
    GenServer.start_link(
      __MODULE__,
      %{
        access_key: System.get_env("ACCESS_KEY"),
        secret_access: System.get_env("SECRET_ACCESS")
      },
      name: __MODULE__
    )
  end

  def init(args) do
    schedule_refresh_token(DateTime.utc_now())
    {:ok, %__MODULE__{access_key: args[:access_key], secret_access: args[:secret_access]}}
  end

  def get_security_token do
    GenServer.call(__MODULE__, :get_security_token)
  end

  def handle_info(:refresh_token, state) do
    {security_token, expires_at} = generate_security_token(state.access_key, state.secret_access)

    schedule_refresh_token(expires_at)

    new_state = %{
      state
      | security_token: security_token,
        expires_at: expires_at
    }

    {:noreply, new_state}
  end

  def handle_call(:get_security_token, _from, state) do
    {:reply, state.security_token, state}
  end

  def generate_security_token(_access_key, _secret_access) do
    {security_token(), expire_at()}
  end

  defp schedule_refresh_token(expire_at) do
    current_time = DateTime.utc_now()
    time_difference = DateTime.diff(expire_at, current_time)

    Process.send_after(self(), :refresh_token, time_difference * @miliseconds_in_second)
  end

  defp security_token do
    :crypto.strong_rand_bytes(@security_token_size)
    |> Base.encode64()
  end

  defp expire_at do
    DateTime.utc_now()
    |> DateTime.add(@expires_in_seconds)
  end

  def format_status(_reason, [pdict, state]) do
    {:ok,
     [
       pdict,
       %{
         state
         | access_key: "<sensitive_data>",
           secret_access: "<sensitive_data>",
           security_token: "<sensitive_data>"
       }
     ]}
  end

  defimpl Inspect, for: SecurityTokenManager do
    def inspect(%SecurityTokenManager{} = state, opts) do
      Inspect.Map.inspect(
        %{
          access_key: "<redacted>",
          secret_access: "<redacted>",
          security_token: "<redacted>",
          expires_at: state.expires_at
        },
        opts
      )
    end
  end
end
