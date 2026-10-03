// Synthetic navigation fixture; do not run or deploy.
public class Accounts {
    @GetMapping("/accounts")
    public Object search(String query) {
        return database.executeQuery(query);
    }
}
