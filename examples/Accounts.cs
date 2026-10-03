// Synthetic navigation fixture; do not run or deploy.
public class Accounts {
    [HttpGet]
    public string Search(string query) {
        return database.Execute(query);
    }
}
