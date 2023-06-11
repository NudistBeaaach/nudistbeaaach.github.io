library ieee;
use ieee.std_logic_1164.all;
use work.cubik_pkg.all;

entity cubik_cipher is
    generic (round_div_2 : positive := 8);
    port (
    resetn : in  std_logic;
    clk    : in  std_logic;
-- key
    key    : in std_logic_vector(1023 downto 0);
-- d in
    d_v_i  : in  std_logic;
    d_i    : in  std_logic_vector(data_width-1 downto 0);
-- dout
    d_c    : out std_logic_vector(data_width-1 downto 0);
    d_v_c  : out  std_logic
  );
end entity;

architecture rtl of cubik_cipher is
    constant key_w : positive := 576;
    type state is (idle, engine);
    signal current_state,next_state    : state;
    signal ctr_round : natural range 0 to 9;
	 signal load : std_logic;
    signal end_ctr,cmd_ctr : std_logic;
    signal rkey :  std_logic_vector(key_w-1 downto 0);
    signal reg_cipher :  std_logic_vector(d_i'range);
begin


  process (clk, resetn) is
  begin
    if resetn = '0' then
      ctr_round <= 0;
    elsif rising_edge(clk) then
      if cmd_ctr = '0' then
        ctr_round <= 0;
      else
        ctr_round <= ctr_round + 1;
      end if;
    end if;
  end process;
end_ctr <= '1' when ctr_round = 9 else '0';

process (clk, resetn) is
begin
      if resetn = '0' then
          current_state <= idle;
      elsif rising_edge(clk) then
          current_state <= next_state;
      end if;
end process;

process (clk, resetn) is
begin
      if resetn = '0' then
          reg_cipher <= (others => '0');
      elsif rising_edge(clk) then
          if d_v_i = '1' and ctr_round = 0 then
            reg_cipher <= d_i;
          else 
            reg_cipher <= round(reg_cipher, rkey);
          end if;
      end if;
end process;
d_c <= reg_cipher;

process (current_state, end_ctr, d_v_i)
begin
  d_v_c <= '0';
  case current_state is
----------------------------
    when idle    =>
    if d_v_i = '1' then
      next_state <= engine;
    end if;
    cmd_ctr <= '0';
----------------------------
    when engine  =>
    if end_ctr = '1' then
      next_state <= idle;
      d_v_c <= '1';
      cmd_ctr <= '0';
    else 
      cmd_ctr <= '1';    
    end if;
----------------------------
end case;
end process;

  key_engine : entity work.key_randomize
  generic map(key_w => key_w)
  port map (
    resetn => resetn,
    clk    => clk,
    load   => d_v_i,
    key    => key,
    key_r  => rkey
  );
end architecture;