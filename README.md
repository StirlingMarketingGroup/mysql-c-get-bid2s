# MySQL C_GET_BID2S

A c variant of my `get_bid2s` function for collecting bid2s from text and returning them hex encoded for use in full text indexes. https://github.com/StirlingMarketingGroup/mysql-get-bid2s

> Returns the possibly b64u and hex encoded bid2s separated by spaces in the given text.

## Usage

```sql
`c_get_bid2s` ( string `Text` )
```

 - `` `Text` ``
   - The haystack to search.

## Dependencies

Debian / Ubuntu

```shell
sudo apt update
sudo apt install libmysqlclient-dev
```

## Installing

You can find your MySQL plugin directory by running this MySQL query

```sql
select @@plugin_dir;
```

then replace `/usr/lib/mysql/plugin` below with your MySQL plugin directory.

```shell
git clone https://github.com/StirlingMarketingGroup/mysql-c-get-bid2s.git
cd mysql-c-get-bid2s
gcc -O3 -I/usr/include/mysql -o c_get_bid2s.so -shared c_get_bid2s.c -fPIC
sudo cp c_get_bid2s.so /usr/lib/mysql/plugin/c_get_bid2s.so
```

Enable the function in MySQL by running this MySQL query

```sql
create function`c_get_bid2s`returns string soname'c_get_bid2s.so';
```