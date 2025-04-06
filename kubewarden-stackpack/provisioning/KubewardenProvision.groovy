import groovy.json.JsonSlurper
import com.stackstate.stackpack.ProvisioningScript
import com.stackstate.stackpack.ProvisioningContext
import com.stackstate.stackpack.ProvisioningIO
import com.stackstate.stackpack.Version

class KubewardenProvision extends ProvisioningScript {
  KubewardenProvision(ProvisioningContext context) {
    super(context)
  }

  @Override
  ProvisioningIO<scala.Unit> preInstall(Map<String, Object> config) {
    return context().stackPack().importSnapshot("templates/kubewarden.stj")
  }

  @Override
  ProvisioningIO<scala.Unit> upgrade(Map<String, Object> config, Version current) {
    return preInstall(config)
  }
}
