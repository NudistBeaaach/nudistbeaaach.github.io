library ieee;
use ieee.std_logic_1164.all;

entity key_randomize is
    generic (key_w : positive := 32);
    port (
	resetn : in std_logic;
    clk    : in std_logic;
    load   : in std_logic;
    key    : in std_logic_vector(1023 downto 0);
    key_r  : out std_logic_vector(key_w-1 downto 0)
  );
end entity;

architecture rtl of key_randomize is
signal reg : std_logic_vector(key'range);
begin
    process (clk,resetn) is
    begin
        if resetn = '0' then
            reg  <= (others => '1');
        elsif rising_edge(clk) then
            if load = '1' then
                reg <= key;
            else
                reg      <= reg(reg'length-2 downto 0) & reg(reg'high);
                reg(24)  <= reg(23) xor reg(reg'high);
                reg(421) <= reg(420) xor reg(reg'high);
                reg(476) <= reg(475) xor reg(reg'high);
                reg(545) <= reg(544) xor reg(reg'high);
                reg(923) <= reg(922) xor reg(reg'high);
            end if;
        end if;
    end process;
    key_r <= reg(key_r'range);
end architecture;