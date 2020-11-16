## LicensePoint .Net Class

## Usage

### static readonly LP api = new LP("My First App", "mD0zOOJS9GIK59QKwqZgYyuHwNrnEGi0jiA87j1g0J15T", "1.0");

### api.Connect();

## Single License Login:

if (api.licenseLogin(license.Text))
            {
                MessageBox.Show("Successfully logged in!" +Info.Expires, Auth.appName, MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Error Log In", Auth.appName, MessageBoxButtons.OK, MessageBoxIcon.Error);

            }
            
## Register:

if (api.Register(username.Text, password.Text, license.Text))
{
    MessageBox.Show("Successfull!" +Info.Expires, Auth.appName, MessageBoxButtons.OK, MessageBoxIcon.Information);
}else
    {
         MessageBox.Show("Error Log In", Auth.appName, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
    
## Login:
  
  if (api.Login(username.Text, password.Text))
{
   MessageBox.Show("Successfull!" +Info.Expires, Auth.appName, MessageBoxButtons.OK, MessageBoxIcon.Information);
}else
    {
         MessageBox.Show("Error Log In", Auth.appName, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
    
## Extend subscription time:

if (app.ExtendTime(username.Text, password.Text, license.Text))
{
  MessageBox.Show("Successfull!" +Info.Expires, Auth.appName, MessageBoxButtons.OK, MessageBoxIcon.Information);
}else
    {
         MessageBox.Show("Error Log In", Auth.appName, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
