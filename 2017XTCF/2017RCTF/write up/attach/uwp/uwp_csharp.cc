public static string dfdfdfd(string input)
{
    IBuffer buffer = WindowsRuntimeBufferExtensions.AsBuffer(Convert.FromBase64String(input));
    string str_family = Package.get_Current().get_Id().get_FamilyName().Substring(0, 0x10);
    string str_zero = "0000000000000000";
    IBuffer buf_zero = WindowsRuntimeBufferExtensions.AsBuffer(Encoding.get_UTF8().GetBytes(str_zero));
    byte[] buf_family = Encoding.get_UTF8().GetBytes(str_family);
    key = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.get_AesCbcPkcs7()).CreateSymmetricKey(WindowsRuntimeBufferExtensions.AsBuffer(buf_family));

    // key, data, iv
    IBuffer buffer4 = CryptographicEngine.Decrypt(key, buffer, buf_zero);
    return CryptographicBuffer.ConvertBinaryToString(0, buffer4);
}

private void button_Click(object sender, RoutedEventArgs e)
{
    int id;
    if (int.TryParse(this.textBox.get_Text(), out id))
    {
        <>c__DisplayClass4_0 class_;
        ParameterExpression expression;
        ParameterExpression[] expressionArray1 = new ParameterExpression[] { expression };

        select_source = this.conn.Table<flag_table>().Where
          (
           Expression.Lambda<Func<flag_table, bool>>
           (
            (Expression) Expression.Equal
            ((Expression) Expression.Property
             ((Expression) (expression = Expression.Parameter((Type) typeof(flag_table), "p")),
              (MethodInfo) methodof(flag_table.get_Id)),
             (Expression) Expression.Field((Expression) Expression.Constant(class_, (Type) typeof(<>c__DisplayClass4_0)),
                                           fieldof(<>c__DisplayClass4_0.id))),
            expressionArray1)
                 )

          IEnumerable<string> enumerable = Enumerable.Select<flag_table, string> (select_source, delegate (flag_table p) {return p.flag;} );
        foreach (string str in enumerable)
        {
            this.textBlock.put_Text("flag:" + dfdfdfd(str));
        }
    }
}
