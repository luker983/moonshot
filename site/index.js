import {
  LitElement,
  html,
} from "https://cdn.jsdelivr.net/gh/lit/dist@3/core/lit-core.min.js";
import "./bar.js";
import "./health.js";
import "./location.js";

export class TelemetryModule extends LitElement {
  static properties = {
    data: { type: Object },
  };

  constructor() {
    super();
    this.data = {};
  }

  async connectedCallback() {
    super.connectedCallback();
    this._timer = window.setInterval(this._pollData.bind(this), 10000);
    this._pollData();
  }

  async disconnectedCallback() {
    window.clearInterval(this._timer);
    super.disconnectedCallback();
  }

  async _pollData() {
    const response = await fetch("/data", {
      method: "GET",
    });
    this.data = await response.json();
  }

  createRenderRoot() {
    return this;
  }

  render() {
    return html` <div class="container text-center">
      <h1 class="m-5 p-1">LunaLink 6X-1 Telemetry Module</h1>
      <div class="row m-5">
        <div class="col">
          <bar-metric
            name="Battery"
            value="${this.data.Battery}"
            max="100"
            icon="bi-battery-half"
          ></bar-metric>
        </div>
        <div class="col">
          <bar-metric
            name="Temperature"
            value="${this.data.Temp + 183}"
            max="289"
            icon="bi-thermometer-half"
          ></bar-metric>
        </div>
      </div>
      <div class="row m-5">
        <div class="col">
          <health-metric .healthy="${this.data.Healthy}"></health-metric>
        </div>
        <div class="col">
          <location-metric
            lat="${this.data.Latitude}"
            lon="${this.data.Longitude}"
          ></location-metric>
        </div>
      </div>
    </div>`;
  }
}
customElements.define("telemetry-module", TelemetryModule);
