library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;
-----------------------------------------------------------
--                      FUNCTIONS
-----------------------------------------------------------
-- Primitive polynomial = D^9+D^4+1  -- GF(512)
-----------------------------------------------------------

package cubik_pkg is
subtype nonaire  is std_logic_vector (8 downto 0);
constant square_size  : positive := 4;
constant row_width    : positive := square_size*nonaire'length;
constant matrix_width : positive := square_size**2*nonaire'length;
constant data_width   : positive := square_size**3*nonaire'length;
type row      is array (0 to square_size-1) of nonaire; 
type matrix   is array (0 to square_size-1) of row;
type matrix2   is array (0 to 10) of row;
type cubix    is array (0 to square_size-1) of matrix;
type matrix_c is array (0 to square_size-1,0 to square_size-1) of nonaire;
type matrix_t is array (0 to square_size-1) of matrix_c;
--      m(x,y)            y     0            1         2          3          x
constant m_0 : matrix_c :=(('0'&x"03", '0'&x"00", '0'&x"02", '0'&x"06"),  -- 0
                           ('0'&x"06", '0'&x"03", '0'&x"00", '0'&x"02"),  -- 1
                           ('0'&x"02", '0'&x"06", '0'&x"03", '0'&x"00"),  -- 2
                           ('0'&x"00", '0'&x"02", '0'&x"06", '0'&x"03")); -- 3 

constant m_1 : matrix_c :=(('0'&x"06", '0'&x"04", '0'&x"03", '0'&x"00"),
                           ('0'&x"00", '0'&x"06", '0'&x"04", '0'&x"03"),
                           ('0'&x"03", '0'&x"00", '0'&x"06", '0'&x"04"),
                           ('0'&x"04", '0'&x"03", '0'&x"00", '0'&x"06"));

constant m_2 : matrix_c :=(('0'&x"04", '0'&x"00", '0'&x"09", '0'&x"03"),
                           ('0'&x"03", '0'&x"04", '0'&x"00", '0'&x"09"),
                           ('0'&x"09", '0'&x"03", '0'&x"04", '0'&x"00"),
                           ('0'&x"00", '0'&x"09", '0'&x"03", '0'&x"04"));

constant m_3 : matrix_c :=(('0'&x"02", '0'&x"04", '0'&x"00", '0'&x"09"),
                           ('0'&x"09", '0'&x"02", '0'&x"04", '0'&x"00"),
                           ('0'&x"00", '0'&x"09", '0'&x"02", '0'&x"04"),
                           ('0'&x"04", '0'&x"00", '0'&x"09", '0'&x"02"));
  
function swap_rows  (c  : cubix) return cubix;
function times2     (n  : nonaire) return nonaire;
function times      (n1 : nonaire; 
                     n2 : nonaire) return nonaire;
function reverse    (n  : nonaire) return nonaire;
function mixrow     (r  : row; m : matrix_c) return row;
function mixmatrix  (m  : matrix; 
                     mt : matrix_t) return matrix;
function mixcubix   (c  : cubix;
                     mt : matrix_t) return cubix;
function shiftmt    (mt : matrix_t; p : natural) return matrix_t;
function roundrow   (r : row;  key : std_logic_vector(35 downto 0)) return row;
function roundmatrix(m : matrix;  key : std_logic_vector(143 downto 0)) return matrix;
function roundcubix (c : cubix;  key : std_logic_vector(575 downto 0)) return cubix;
function slv2cubix  (data : std_logic_vector(data_width-1 downto 0)) return cubix;
function slv2matrix (data : std_logic_vector(matrix_width-1 downto 0)) return matrix;
function slv2row    (data : std_logic_vector(row_width-1 downto 0)) return row;
function cubix2slv  (c : cubix) return std_logic_vector;
function matrix2slv (m : matrix ) return std_logic_vector;
function row2slv    (r :row) return std_logic_vector;

function round(data : std_logic_vector(data_width-1 downto 0) ;  key : std_logic_vector(575 downto 0)) return std_logic_vector;

end cubik_pkg;

----------------------------------------------------------------------
package body cubik_pkg is

  
  function swap_rows (c: cubix) return cubix is
  variable tmp :cubix;
  begin
    tmp (0)(0) := c(1)(1);
    tmp (0)(1) := c(3)(3);
    tmp (0)(2) := c(2)(2);
    tmp (0)(3) := c(2)(1);
    tmp (1)(0) := c(3)(1);
    tmp (1)(1) := c(2)(0);
    tmp (1)(2) := c(0)(1);
    tmp (1)(3) := c(1)(2);
    tmp (2)(0) := c(1)(0);
    tmp (2)(1) := c(0)(3);
    tmp (2)(2) := c(2)(3);
    tmp (2)(3) := c(3)(0);
    tmp (3)(0) := c(3)(2);
    tmp (3)(1) := c(0)(0);
    tmp (3)(2) := c(1)(3);
    tmp (3)(3) := c(0)(2);
    return tmp;
  end swap_rows; 
  
  function times2     (n : nonaire) return nonaire is
    variable tmp :nonaire;
  begin
    tmp := n(7 downto 4) & (n(3) xor n(8)) & n(2 downto 0) & n(8);
    return tmp;
  end times2;   

  function times(n1: nonaire; n2: nonaire) return nonaire is
    variable tmp : nonaire;
   begin
    tmp := (others => '0');
    for i in n1'range loop
        if n1(i) = '1' then
            tmp := tmp xor n2;
        end if;
        if i > 0 then
            tmp := times2(tmp); -- GF_mult2 : function qui multiplie par 2
        end if;
    end loop;
    return tmp;
   end times;
  
  function reverse(n : nonaire) return nonaire is -- montgommery ladder
      variable r0,r1 : nonaire;
      constant k     : nonaire := ( 0 => '0', others => '1');
  begin
      r0 := n;
      r1 := times(n,n);
      for i in nonaire'length-2 downto 0 loop
          if k(i) = '0' then
              r1 := times(r1,r0);
              r0 := times(r0,r0);
          elsif k(i) = '1' then
              r0 := times(r1,r0);
              r1 := times(r1,r1);
          end if;            
      end loop;
      return r0;
  end reverse;
  
  function mixrow(r : row; m : matrix_c) return row is
    variable tmp : row;
  begin
    for i in row'range loop
        tmp(i) := times(m(i,0),r(0)) xor times(m(i,1),r(1)) xor times(m(i,2),r(2)) xor times(m(i,3),r(3));
    end loop;
    return tmp;
  end mixrow;

  function mixmatrix(m : matrix; mt : matrix_t) return matrix is
    variable tmp : matrix;
  begin
    for j in matrix'range loop
      tmp(j) := mixrow(m(j),mt(j));
    end loop;
    return tmp;
  end mixmatrix;

  function shiftmt     (mt : matrix_t; p : natural) return matrix_t is
    variable tmp : matrix_t;
  begin
    for l in matrix_t'range loop
      tmp(l) := mt((l+p) mod square_size);
    end loop;
    return tmp;
  end shiftmt; 

  function mixcubix(c : cubix;  mt : matrix_t) return cubix is
    variable tmp : cubix;
  begin
    for k in cubix'range loop
      tmp(k) := mixmatrix(c(k),shiftmt(mt,k)); 
    end loop;
    return tmp;
  end mixcubix;

  function roundrow(r : row;  key : std_logic_vector(35 downto 0)) return row is
    variable tmp : row;
  begin
    for i in row'range loop
      tmp(i) := r(i) xor key(9*(i+1)-1 downto 9*i); 
    end loop;
    return tmp;
  end roundrow;

  function roundmatrix(m : matrix;  key : std_logic_vector(143 downto 0)) return matrix is
    variable tmp : matrix;
  begin
    for j in matrix'range loop
      tmp(j) := roundrow(m(j),key(36*(j+1)-1 downto 36*j)); 
    end loop;
    return tmp;
  end roundmatrix;

  function roundcubix(c : cubix;  key : std_logic_vector(575 downto 0)) return cubix is
    variable tmp : cubix;
  begin
    for k in cubix'range loop
      tmp(k) := roundmatrix(c(k),key(144*(k+1)-1 downto 144*k)); 
    end loop;
    return tmp;
  end roundcubix;

  function slv2cubix(data : std_logic_vector(data_width-1 downto 0)) return cubix is
    variable tmp : cubix;
  begin
    for k in cubix'range loop
      tmp(k) := slv2matrix(data(144*(k+1)-1 downto 144*k));
    end loop;
    return tmp;
  end slv2cubix;

  function cubix2slv(c : cubix) return std_logic_vector is
    variable tmp : std_logic_vector(data_width-1 downto 0);
  begin
    for k in cubix'range loop
      tmp(144*(k+1)-1 downto 144*k) := matrix2slv(c(k)); 
    end loop;
    return tmp;
  end cubix2slv;

  function slv2matrix(data : std_logic_vector(matrix_width-1 downto 0)) return matrix is
    variable tmp : matrix;
  begin
    for j in matrix'range loop
      tmp(j) := slv2row(data(36*(j+1)-1 downto 36*j)); 
    end loop;
    return tmp;
  end slv2matrix;

  function matrix2slv(m : matrix ) return std_logic_vector is
    variable tmp : std_logic_vector(matrix_width-1 downto 0);
  begin
    for j in matrix'range loop
      tmp(36*(j+1)-1 downto 36*j) := row2slv(m(j)); 
    end loop;
    return tmp;
  end matrix2slv;

  function slv2row(data : std_logic_vector(row_width-1 downto 0)) return row is
    variable tmp : row;
  begin
    for i in row'range loop
      tmp(i) := data(9*(i+1)-1 downto 9*i); 
    end loop;
    return tmp;
  end slv2row;

  function row2slv(r :row) return std_logic_vector is
    variable tmp : std_logic_vector(row_width-1 downto 0);
  begin
    for i in row'range loop
      tmp(9*(i+1)-1 downto 9*i) := r(i); 
    end loop;
    return tmp;
  end row2slv;

  function round(data : std_logic_vector(data_width-1 downto 0) ;  key : std_logic_vector(575 downto 0)) return std_logic_vector is
    variable tmp : cubix;
    variable data_out : std_logic_vector(data'range);
  begin
    tmp := slv2cubix(data);
    tmp := mixcubix(tmp, (m_0,m_1,m_2,m_3));
    tmp := roundcubix(tmp, key);
    tmp := swap_rows(tmp);
    data_out := cubix2slv(tmp);
    return data_out;
  end round;


end cubik_pkg;

